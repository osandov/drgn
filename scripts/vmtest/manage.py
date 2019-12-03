#!/usr/bin/env python3

import aiohttp
import argparse
import asyncio
import difflib
import getpass
import io
import json
import logging
import multiprocessing
import os
import os.path
import re
import shlex
import sys
import time


logger = logging.getLogger('asyncio')


KERNEL_ORG_JSON = 'https://www.kernel.org/releases.json'


DEFCONFIG = """\
# Minimal configuration for booting into the root filesystem image and building
# and testing drgn on a live kernel.

CONFIG_SMP=y

# No modules to simplify installing the kernel into the root filesystem image.
CONFIG_MODULES=n

# We run the tests in KVM.
CONFIG_HYPERVISOR_GUEST=y
CONFIG_KVM_GUEST=y
CONFIG_PARAVIRT=y
CONFIG_PARAVIRT_SPINLOCKS=y

# Minimum requirements for booting up.
CONFIG_DEVTMPFS=y
CONFIG_EXT4_FS=y
CONFIG_PCI=y
CONFIG_PROC_FS=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SYSFS=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_PCI=y

# drgn needs /proc/kcore for live debugging.
CONFIG_PROC_KCORE=y
# In some cases, it also needs /proc/kallsyms.
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y

# drgn needs debug info.
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF4=y

# Some important information in VMCOREINFO is initialized in the kexec code for
# some reason.
CONFIG_KEXEC=y

# In case we need to refer to the kernel config in the future.
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
"""


DROPBOX_API_URL = 'https://api.dropboxapi.com'
CONTENT_API_URL = 'https://content.dropboxapi.com'


def humanize_size(n, precision=1):
    n = float(n)
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(n) < 1024:
            break
        n /= 1024
    else:
        unit = 'Yi'
    if n.is_integer():
        precision = 0
    return f'{n:.{precision}f}{unit}B'


def humanize_duration(seconds):
    seconds = round(seconds)
    return f'{seconds // 60}m{seconds % 60}s'


# Like aiohttp.ClientResponse.raise_for_status(), but includes the response
# body.
async def raise_for_status_body(resp):
    if resp.status >= 400:
        message = resp.reason
        body = await resp.text()
        if body:
            message += ': ' + body
        raise aiohttp.ClientResponseError(resp.request_info, resp.history,
                                          status=resp.status, message=message,
                                          headers=resp.headers)


async def get_kernel_org_releases(http_client):
    async with http_client.get(KERNEL_ORG_JSON, raise_for_status=True) as resp:
        releases = (await resp.json())['releases']
        return [
            'v' + release['version'] for release in releases
            if release['moniker'] in {'mainline', 'stable', 'longterm'}
            # 3.16 seems to be missing "x86/build/64: Force the linker to use
            # 2MB page size", so it doesn't even boot. It's projected to be EOL
            # in June 2020 (https://www.kernel.org/category/releases.html), and
            # 3.x is ancient anyways, so don't bother.
            and not release['version'].startswith('3.')
        ]


async def get_shared_files(http_client, token):
    headers = {'Authorization': 'Bearer ' + token}
    params = {
        'path': '/Public',
        'direct_only': True,
    }
    async with http_client.post(DROPBOX_API_URL + '/2/sharing/list_shared_links',
                                headers=headers, json=params) as resp:
        await raise_for_status_body(resp)
        for link in (await resp.json())['links']:
            if link['.tag'] != 'folder':
                continue
            try:
                visibility = link['link_permissions']['resolved_visibility']['.tag']
            except KeyError:
                continue
            if visibility == 'public':
                break
        else:
            raise Exception('shared folder link not found')

    # The Dropbox API doesn't provide a way to get the links for entries inside
    # of a shared folder, so we're forced to scrape them from the webpage and
    # XHR endpoint.
    method = 'GET'
    url = link['url']
    cookies = {}
    data = None
    files = []
    while True:
        async with http_client.request(method, url, cookies=cookies,
                                       data=data) as resp:
            if method == 'GET':
                resp.raise_for_status()
                body = await resp.text()
                match = re.search(r'"\{\\"shared_link_infos\\".*[^\\]\}"',
                                  body)
                obj = json.loads(json.loads(match.group()))
                method = 'POST'
                url = 'https://www.dropbox.com/list_shared_link_folder_entries'
                cookies['t'] = resp.cookies['t']
                data = {
                    't': cookies['t'].value,
                    'link_key': obj['folder_share_token']['linkKey'],
                    'link_type': 's',
                    'secure_hash': obj['folder_share_token']['secureHash'],
                    'sub_path': '',
                }
            else:
                await raise_for_status_body(resp)
                obj = await resp.json()
        files.extend(
            (entry['filename'],
             re.sub(r'([?&])dl=0(&|$)', r'\1dl=1\2', entry['href']))
            for entry in obj['entries']
        )
        if not obj['has_more_entries']:
            break
        data['voucher'] = obj['next_request_voucher']
    return files


async def get_available_kernel_releases(http_client, token):
    available = set()
    for filename, _ in (await get_shared_files(http_client, token)):
        match = re.fullmatch(r'vmlinux-(\d+)\.(\d+)\.(\d+)(-rc\d+)?\.zst',
                             filename)
        if not match:
            continue
        version = f'v{match.group(1)}.{match.group(2)}'
        if match.group(3) != '0':
            version += '.' + match.group(3)
        if match.group(4):
            version += match.group(4)
        available.add(version)
    return available


async def check_call(*args, **kwds):
    proc = await asyncio.create_subprocess_exec(*args, **kwds)
    returncode = await proc.wait()
    if returncode != 0:
        command = ' '.join(shlex.quote(arg) for arg in args)
        raise Exception(f'Command {command!r} returned non-zero exit status {returncode}')


async def check_output(*args, **kwds):
    proc = await asyncio.create_subprocess_exec(*args, **kwds,
                                                stdout=asyncio.subprocess.PIPE)
    stdout = (await proc.communicate())[0]
    if proc.returncode != 0:
        command = ' '.join(shlex.quote(arg) for arg in args)
        raise Exception(f'Command {command!r} returned non-zero exit status {proc.returncode}')
    return stdout


async def compress_file(in_path, out_path, *args, **kwds):
    logger.info('compressing %r', in_path)
    start = time.monotonic()
    await check_call('zstd', '-T0', '-19', '-q', in_path, '-o', out_path,
                     *args, **kwds)
    elapsed = time.monotonic() - start
    logger.info('compressed %r in %s', in_path, humanize_duration(elapsed))


async def build_kernel(commit, build_dir, log_file):
    await check_call('git', 'checkout', commit, stdout=log_file,
                     stderr=asyncio.subprocess.STDOUT)

    with open(os.path.join(build_dir, '.config'), 'w') as config_file:
        config_file.write(DEFCONFIG)

    logger.info('building %s', commit)
    start = time.monotonic()
    kbuild_args = ['KBUILD_BUILD_USER=drgn', 'KBUILD_BUILD_HOST=drgn',
                   'O=' + build_dir, '-j', str(multiprocessing.cpu_count())]
    await check_call('make', *kbuild_args, 'olddefconfig', 'all',
                     stdout=log_file, stderr=asyncio.subprocess.STDOUT)
    elapsed = time.monotonic() - start
    logger.info('built %s in %s', commit, humanize_duration(elapsed))

    vmlinux = os.path.join(build_dir, 'vmlinux')
    release, image_name = (await asyncio.gather(
        compress_file(vmlinux, vmlinux + '.zst', stdout=log_file,
                      stderr=asyncio.subprocess.STDOUT),
        check_output('make', *kbuild_args, '-s', 'kernelrelease',
                     stderr=log_file),
        check_output('make', *kbuild_args, '-s', 'image_name',
                     stderr=log_file),
    ))[1:]
    return build_dir, release.decode().strip(), image_name.decode().strip()


async def try_build_kernel(commit):
    proc = await asyncio.create_subprocess_exec(
        'git', 'rev-parse', '--verify', '-q', commit + '^{commit}',
        stdout=asyncio.subprocess.DEVNULL)
    if (await proc.wait()) != 0:
        logger.error('unknown revision: %s', commit)
        return None

    build_dir = 'build-' + commit
    try:
        log_path = os.path.join(build_dir, 'build.log')
        logger.info('preparing %r; logs in %r', build_dir, log_path)
        os.mkdir(build_dir, 0o755)
        with open(log_path, 'w') as log_file:
            try:
                return await build_kernel(commit, build_dir, log_file)
            except Exception:
                logger.exception('building %s failed; see %r', commit,
                                 log_path)
                return None
    except Exception:
        logger.exception('preparing %r failed', build_dir)
        return None


class Uploader:
    CHUNK_SIZE = 8 * 1024 * 1024

    def __init__(self, http_client, token):
        self._http_client = http_client
        self._token = token
        self._pending = []

    async def _upload_file_obj(self, file, commit):
        headers = {
            'Authorization': 'Bearer ' + self._token,
            'Content-Type': 'application/octet-stream',
        }
        offset = 0
        session_id = None
        while True:
            data = file.read(Uploader.CHUNK_SIZE)
            last = len(data) < Uploader.CHUNK_SIZE
            if session_id is None:
                if last:
                    endpoint = 'upload'
                    params = commit
                else:
                    endpoint = 'upload_session/start'
                    params = {}
            else:
                params = {
                    'cursor': {
                        'offset': offset,
                        'session_id': session_id,
                    },
                }
                if last:
                    endpoint = 'upload_session/finish'
                    params['commit'] = commit
                else:
                    endpoint = 'upload_session/append_v2'
            offset += len(data)
            headers['Dropbox-API-Arg'] = json.dumps(params)
            url = CONTENT_API_URL + '/2/files/' + endpoint
            async with self._http_client.post(url, headers=headers,
                                              data=data) as resp:
                await raise_for_status_body(resp)
                if endpoint == 'upload_session/start':
                    session_id = (await resp.json())['session_id']
            if last:
                break

    async def _try_upload_file_obj(self, file, commit):
        try:
            logger.info('uploading %r', commit['path'])
            start = time.monotonic()
            await self._upload_file_obj(file, commit)
            elapsed = time.monotonic() - start
            logger.info('uploaded %r in %s', commit['path'],
                        humanize_duration(elapsed))
            return True
        except Exception:
            logger.exception('uploading %r failed', commit['path'])
            return False

    async def _try_upload_file(self, path, commit):
        try:
            logger.info('uploading %r to %r', path, commit['path'])
            start = time.monotonic()
            with open(path, 'rb') as f:
                await self._upload_file_obj(f, commit)
            elapsed = time.monotonic() - start
            logger.info('uploaded %r to %r in %s', path, commit['path'],
                        humanize_duration(elapsed))
            return True
        except Exception:
            logger.exception('uploading %r to %r failed', path, commit['path'])
            return False

    @staticmethod
    def _make_commit(dst_path, *, mode=None, autorename=None):
        commit = {'path': dst_path}
        if mode is not None:
            commit['mode'] = mode
        if autorename is not None:
            commit['autorename'] = autorename
        return commit

    def queue_file_obj(self, file, *args, **kwds):
        commit = self._make_commit(*args, **kwds)
        task = asyncio.create_task(self._try_upload_file_obj(file, commit))
        self._pending.append((commit['path'], task))

    def queue_file(self, src_path, *args, **kwds):
        commit = self._make_commit(*args, **kwds)
        task = asyncio.create_task(self._try_upload_file(src_path, commit))
        self._pending.append((commit['path'], task))

    async def wait(self):
        succeeded = []
        failed = []
        for path, task in self._pending:
            if (await task):
                succeeded.append(path)
            else:
                failed.append(path)
        self._pending.clear()
        return succeeded, failed


async def download_index(http_client, token):
    params = {'path': '/Public/INDEX'}
    headers = {
        'Authorization': 'Bearer ' + token,
        'Dropbox-API-Arg': json.dumps(params)
    }
    url = CONTENT_API_URL + '/2/files/download'
    async with http_client.post(url, headers=headers) as resp:
        await raise_for_status_body(resp)
        return await resp.text()


async def update_index(http_client, token, uploader):
    try:
        logger.info('downloading index and listing shared folder')
        old_index, files = await asyncio.gather(
            download_index(http_client, token),
            get_shared_files(http_client, token),
        )

        old_lines = old_index.splitlines(keepends=True)
        lines = sorted(filename + '\t' + link + '\n'
                       for filename, link in files)
        if lines == old_lines:
            logger.info('INDEX is up to date')
            return True

        diff = difflib.unified_diff(old_lines, lines, fromfile='a/INDEX',
                                    tofile='b/INDEX')
        logger.info('updating INDEX:\n%s', ''.join(diff).rstrip('\n'))
        uploader.queue_file_obj(io.BytesIO(''.join(lines).encode()),
                                '/Public/INDEX', mode='overwrite')
        succeeded, failed = await uploader.wait()
        return not failed
    except Exception:
        logger.exception('updating INDEX failed')
        return False


async def main():
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(name)s:%(message)s',
                        level=logging.INFO)

    parser = argparse.ArgumentParser(
        description='Tool for managing drgn vmtest kernel builds and files')
    parser.add_argument('-b', '--build', type=str, action='append',
                        metavar='COMMIT',
                        help='build the given kernel release; may be given multiple times. '
                        'Must be run from a Linux kernel git repository')
    parser.add_argument('-k', '--build-kernel-org', action='store_true',
                        help='build new kernels listed on kernel.org')
    parser.add_argument('-u', '--upload', action='store_true',
                        help='upload built kernels')
    parser.add_argument('-U', '--upload-file', type=str, action='append',
                        dest='upload_files', metavar=('SRC_PATH', 'DST_PATH'),
                        nargs=2, help='upload the given file; may be given multiple times')
    parser.add_argument('-i', '--index', action='store_true',
                        help='update the INDEX file')
    args = parser.parse_args()

    if ((args.build or args.build_kernel_org) and
            (not os.path.exists('.git') or not os.path.exists('kernel'))):
        sys.exit('-b/-k must be run from linux.git')

    if args.upload or args.upload_files or args.index:
        if os.isatty(sys.stdin.fileno()):
            dropbox_token = getpass.getpass('Enter Dropbox app API token: ')
        else:
            dropbox_token = input()

    builds_succeeded = []
    builds_failed = []
    uploads_succeeded = []
    uploads_failed = []

    async with aiohttp.ClientSession(trust_env=True) as http_client:
        # dict rather than set to preserve insertion order.
        to_build = {build: True for build in (args.build or ())}
        if args.build_kernel_org:
            try:
                logger.info('getting list of kernel.org releases and available releases')
                kernel_org, available = await asyncio.gather(
                    get_kernel_org_releases(http_client),
                    get_available_kernel_releases(http_client, dropbox_token),
                )
                logger.info('kernel.org releases: %s', ', '.join(kernel_org))
                logger.info('available releases: %s',
                            ', '.join(sorted(available)))
                for kernel in kernel_org:
                    if kernel not in available:
                        to_build[kernel] = True
            except Exception:
                logger.exception('failed to get kernel.org releases and/or available releases')
                sys.exit(1)

        if args.upload or args.upload_files or args.index:
            uploader = Uploader(http_client, dropbox_token)

        for src_path, dst_path in (args.upload_files or ()):
            uploader.queue_file(src_path, dst_path, autorename=False)

        if to_build:
            logger.info('releases to build: %s', ', '.join(to_build))
        for kernel in to_build:
            result = await try_build_kernel(kernel)
            if result is None:
                builds_failed.append(kernel)
                continue
            builds_succeeded.append(kernel)
            build_dir, release, image_name = result
            if args.upload:
                uploader.queue_file(os.path.join(build_dir, 'vmlinux.zst'),
                                    f'/Public/vmlinux-{release}.zst',
                                    autorename=False)
                uploader.queue_file(os.path.join(build_dir, image_name),
                                    f'/Public/{os.path.basename(image_name)}-{release}',
                                    autorename=False)

        if args.upload or args.upload_files:
            succeeded, failed = await uploader.wait()
            uploads_succeeded.extend(succeeded)
            uploads_failed.extend(failed)

        if builds_succeeded:
            logger.info('successfully built: %s', ', '.join(builds_succeeded))
        if builds_failed:
            logger.error('builds failed: %s', ', '.join(builds_failed))
        if uploads_succeeded:
            logger.info('successfully uploaded: %s',
                        ', '.join(uploads_succeeded))
        if uploads_failed:
            logger.info('uploads failed: %s', ', '.join(uploads_failed))

        if builds_failed or uploads_failed:
            logger.error('builds and/or uploads failed; exiting')
            sys.exit(1)

        if (args.index and
                not await update_index(http_client, dropbox_token, uploader)):
            sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())
