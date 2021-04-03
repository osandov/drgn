# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import asyncio
import difflib
import getpass
import io
import json
import logging
import os
from pathlib import Path
import re
import shlex
import shutil
import sys
import time
from typing import (
    Any,
    AsyncGenerator,
    BinaryIO,
    Dict,
    List,
    Optional,
    Sequence,
    Set,
    SupportsFloat,
    SupportsRound,
    TextIO,
    Tuple,
)
import urllib.parse

import aiohttp
from yarl import URL

from util import nproc

logger = logging.getLogger(__name__)


KERNEL_CONFIG_PATH = Path(__file__).parent / "config"

KERNEL_ORG_JSON = "https://www.kernel.org/releases.json"

DROPBOX_API_URL = "https://api.dropboxapi.com"
CONTENT_API_URL = "https://content.dropboxapi.com"


def humanize_size(n: SupportsFloat, precision: int = 1) -> str:
    n = float(n)
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(n) < 1024:
            break
        n /= 1024
    else:
        unit = "Yi"
    if n.is_integer():
        precision = 0
    return f"{n:.{precision}f}{unit}B"


def humanize_duration(seconds: SupportsRound[Any]) -> str:
    seconds = round(seconds)
    return f"{seconds // 60}m{seconds % 60}s"


async def raise_for_status_body(resp: aiohttp.ClientResponse) -> None:
    """
    Like aiohttp.ClientResponse.raise_for_status(), but includes the response
    body.
    """
    if resp.status >= 400:
        message = resp.reason or ""
        body = await resp.text()
        if body:
            if message:
                message += ": "
            message += body
        raise aiohttp.ClientResponseError(
            resp.request_info,
            resp.history,
            status=resp.status,
            message=message,
            headers=resp.headers,
        )


def get_current_localversion() -> str:
    with KERNEL_CONFIG_PATH.open("r") as f:
        match = re.search(r'^CONFIG_LOCALVERSION="([^"]*)"', f.read(), re.MULTILINE)
    return match.group(1) if match else ""


async def get_kernel_org_versions(http_client: aiohttp.ClientSession) -> List[str]:
    async with http_client.get(KERNEL_ORG_JSON, raise_for_status=True) as resp:
        releases = (await resp.json())["releases"]
        return [
            release["version"]
            for release in releases
            if release["moniker"] in {"mainline", "stable", "longterm"}
        ]


async def get_available_kernel_releases(
    http_client: aiohttp.ClientSession, token: str
) -> Set[str]:
    headers = {"Authorization": "Bearer " + token}
    params = {"path": "/Public/x86_64"}
    url = DROPBOX_API_URL + "/2/files/list_folder"
    available = set()
    while True:
        async with http_client.post(url, headers=headers, json=params) as resp:
            if resp.status == 409 and (await resp.json())["error_summary"].startswith(
                "path/not_found/"
            ):
                break
            await raise_for_status_body(resp)
            obj = await resp.json()
        for entry in obj["entries"]:
            if entry[".tag"] != "file":
                continue
            match = re.fullmatch(r"kernel-(.*)\.tar\.zst", entry["name"])
            if match:
                available.add(match.group(1))
        if not obj["has_more"]:
            break
        url = DROPBOX_API_URL + "/2/files/list_folder/continue"
        params = {"cursor": obj["cursor"]}
    return available


class CalledProcessError(Exception):
    def __init__(self, returncode: int, cmd: Sequence[str]) -> None:
        self.returncode = returncode
        self.cmd = cmd

    def __str__(self) -> str:
        command = " ".join(shlex.quote(arg) for arg in self.cmd)
        raise Exception(
            f"Command {command!r} returned non-zero exit status {self.returncode}"
        )


async def check_call(*args: Any, **kwds: Any) -> None:
    proc = await asyncio.create_subprocess_exec(*args, **kwds)
    returncode = await proc.wait()
    if returncode != 0:
        raise CalledProcessError(returncode, args)


async def check_output(*args: Any, **kwds: Any) -> bytes:
    kwds["stdout"] = asyncio.subprocess.PIPE
    proc = await asyncio.create_subprocess_exec(*args, **kwds)
    stdout = (await proc.communicate())[0]
    if proc.returncode:
        raise CalledProcessError(proc.returncode, args)
    return stdout


def getpwd() -> str:
    """
    Get the current working directory in the same way that GCC does. See
    https://gcc.gnu.org/git/?p=gcc.git;a=blob;f=libiberty/getpwd.c;hb=HEAD.
    """
    try:
        pwd = os.environ["PWD"]
        if pwd.startswith("/"):
            pwdstat = os.stat(pwd)
            dotstat = os.stat(".")
            if dotstat.st_ino == pwdstat.st_ino and dotstat.st_dev == pwdstat.st_dev:
                return pwd
    except (KeyError, OSError):
        pass
    return os.getcwd()


async def build_kernel(
    commit: str, build_dir: Path, log_file: TextIO
) -> Tuple[str, Path]:
    """
    Returns built kernel release (i.e., `uname -r`) and image name (e.g.,
    `arch/x86/boot/bzImage`).
    """
    await check_call(
        "git", "checkout", commit, stdout=log_file, stderr=asyncio.subprocess.STDOUT
    )

    shutil.copy(KERNEL_CONFIG_PATH, build_dir / ".config")

    logger.info("building %s", commit)
    start = time.monotonic()
    cflags = f"-fdebug-prefix-map={getpwd() / build_dir}="
    kbuild_args = [
        "KBUILD_BUILD_USER=drgn",
        "KBUILD_BUILD_HOST=drgn",
        "KAFLAGS=" + cflags,
        "KCFLAGS=" + cflags,
        "O=" + str(build_dir),
        "-j",
        str(nproc()),
    ]
    await check_call(
        "make",
        *kbuild_args,
        "olddefconfig",
        "all",
        stdout=log_file,
        stderr=asyncio.subprocess.STDOUT,
    )
    elapsed = time.monotonic() - start
    logger.info("built %s in %s", commit, humanize_duration(elapsed))

    logger.info("packaging %s", commit)
    start = time.monotonic()

    release = (
        (
            await check_output(
                "make", *kbuild_args, "-s", "kernelrelease", stderr=log_file
            )
        )
        .decode()
        .strip()
    )
    image_name = (
        (await check_output("make", *kbuild_args, "-s", "image_name", stderr=log_file))
        .decode()
        .strip()
    )

    install_dir = build_dir / "install"
    modules_dir = install_dir / "lib" / "modules" / release

    await check_call(
        "make",
        *kbuild_args,
        "INSTALL_MOD_PATH=install",
        "modules_install",
        stdout=log_file,
        stderr=asyncio.subprocess.STDOUT,
    )
    # Don't want these symlinks.
    (modules_dir / "build").unlink()
    (modules_dir / "source").unlink()

    vmlinux = modules_dir / "vmlinux"
    await check_call(
        "objcopy",
        "--remove-relocations=*",
        str(build_dir / "vmlinux"),
        str(vmlinux),
        stdout=log_file,
        stderr=asyncio.subprocess.STDOUT,
    )
    vmlinux.chmod(0o644)

    vmlinuz = modules_dir / "vmlinuz"
    shutil.copy(build_dir / image_name, vmlinuz)
    vmlinuz.chmod(0o644)

    tarball = build_dir / "kernel.tar.zst"
    tar_command = ("tar", "-C", str(modules_dir), "-c", ".")
    zstd_command = ("zstd", "-T0", "-19", "-q", "-", "-o", str(tarball))
    pipe_r, pipe_w = os.pipe()
    try:
        tar_proc, zstd_proc = await asyncio.gather(
            asyncio.create_subprocess_exec(
                *tar_command, stdout=pipe_w, stderr=log_file
            ),
            asyncio.create_subprocess_exec(
                *zstd_command,
                stdin=pipe_r,
                stdout=log_file,
                stderr=asyncio.subprocess.STDOUT,
            ),
        )
    finally:
        os.close(pipe_r)
        os.close(pipe_w)
    tar_returncode, zstd_returncode = await asyncio.gather(
        tar_proc.wait(), zstd_proc.wait()
    )
    if tar_returncode != 0:
        raise CalledProcessError(tar_returncode, tar_command)
    if zstd_returncode != 0:
        raise CalledProcessError(zstd_returncode, zstd_command)
    shutil.rmtree(install_dir)
    elapsed = time.monotonic() - start
    logger.info("packaged %s in %s", commit, humanize_duration(elapsed))

    return release, tarball


async def try_build_kernel(commit: str) -> Optional[Tuple[str, Path]]:
    """Returns (kernel release, tarball path) on success, None on error."""
    proc = await asyncio.create_subprocess_exec(
        "git",
        "rev-parse",
        "--verify",
        "-q",
        commit + "^{commit}",
        stdout=asyncio.subprocess.DEVNULL,
    )
    if (await proc.wait()) != 0:
        logger.error("unknown revision: %s", commit)
        return None

    build_dir = Path("build-" + commit)
    try:
        log_path = build_dir / "build.log"
        logger.info("preparing %r; logs in %r", str(build_dir), str(log_path))
        build_dir.mkdir(0o755)
        with log_path.open("w") as log_file:
            try:
                return await build_kernel(commit, build_dir, log_file)
            except Exception:
                logger.exception("building %s failed; see %r", commit, str(log_path))
                return None
    except Exception:
        logger.exception("preparing %r failed", str(build_dir))
        return None


class Uploader:
    CHUNK_SIZE = 8 * 1024 * 1024

    def __init__(self, http_client: aiohttp.ClientSession, token: str) -> None:
        self._http_client = http_client
        self._token = token
        self._pending: List[Tuple[str, asyncio.Task[bool]]] = []

    async def _upload_file_obj(self, file: BinaryIO, commit: Dict[str, Any]) -> None:
        headers = {
            "Authorization": "Bearer " + self._token,
            "Content-Type": "application/octet-stream",
        }
        offset = 0
        session_id = None
        while True:
            data = file.read(Uploader.CHUNK_SIZE)
            last = len(data) < Uploader.CHUNK_SIZE
            if session_id is None:
                if last:
                    endpoint = "upload"
                    params = commit
                else:
                    endpoint = "upload_session/start"
                    params = {}
            else:
                params = {
                    "cursor": {"offset": offset, "session_id": session_id},
                }
                if last:
                    endpoint = "upload_session/finish"
                    params["commit"] = commit
                else:
                    endpoint = "upload_session/append_v2"
            offset += len(data)
            headers["Dropbox-API-Arg"] = json.dumps(params)
            url = CONTENT_API_URL + "/2/files/" + endpoint
            async with self._http_client.post(url, headers=headers, data=data) as resp:
                await raise_for_status_body(resp)
                if endpoint == "upload_session/start":
                    session_id = (await resp.json())["session_id"]
            if last:
                break

    async def _try_upload_file_obj(
        self, file: BinaryIO, commit: Dict[str, Any]
    ) -> bool:
        try:
            logger.info("uploading %r", commit["path"])
            start = time.monotonic()
            await self._upload_file_obj(file, commit)
            elapsed = time.monotonic() - start
            logger.info("uploaded %r in %s", commit["path"], humanize_duration(elapsed))
            return True
        except Exception:
            logger.exception("uploading %r failed", commit["path"])
            return False

    async def _try_upload_file(self, path: str, commit: Dict[str, Any]) -> bool:
        try:
            logger.info("uploading %r to %r", path, commit["path"])
            start = time.monotonic()
            with open(path, "rb") as f:
                await self._upload_file_obj(f, commit)
            elapsed = time.monotonic() - start
            logger.info(
                "uploaded %r to %r in %s",
                path,
                commit["path"],
                humanize_duration(elapsed),
            )
            return True
        except Exception:
            logger.exception("uploading %r to %r failed", path, commit["path"])
            return False

    @staticmethod
    def _make_commit(
        dst_path: str, *, mode: Optional[str] = None, autorename: Optional[bool] = None
    ) -> Dict[str, Any]:
        commit: Dict[str, Any] = {"path": dst_path}
        if mode is not None:
            commit["mode"] = mode
        if autorename is not None:
            commit["autorename"] = autorename
        return commit

    def queue_file_obj(self, file: BinaryIO, *args: Any, **kwds: Any) -> None:
        commit = self._make_commit(*args, **kwds)
        task = asyncio.create_task(self._try_upload_file_obj(file, commit))
        self._pending.append((commit["path"], task))

    def queue_file(self, src_path: str, *args: Any, **kwds: Any) -> None:
        commit = self._make_commit(*args, **kwds)
        task = asyncio.create_task(self._try_upload_file(src_path, commit))
        self._pending.append((commit["path"], task))

    async def wait(self) -> Tuple[List[str], List[str]]:
        """
        Returns list of successfully uploaded paths and list of paths that
        failed to upload.
        """
        succeeded = []
        failed = []
        for path, task in self._pending:
            if await task:
                succeeded.append(path)
            else:
                failed.append(path)
        self._pending.clear()
        return succeeded, failed


async def list_shared_folder(
    http_client: aiohttp.ClientSession, url: str
) -> AsyncGenerator[Tuple[str, bool, str], None]:
    """
    List a Dropbox shared folder. The Dropbox API doesn't provide a way to get
    the links for entries inside of a shared folder, so we're forced to scrape
    them from the webpage and XHR endpoint.

    Generates filename, whether it is a directory, and its shared link.
    """
    method = "GET"
    data = None
    while True:
        async with http_client.request(method, url, data=data) as resp:
            if method == "GET":
                resp.raise_for_status()
                match = re.search(
                    r'"\{\\"shared_link_infos\\".*[^\\]\}"', (await resp.text())
                )
                assert match
                obj = json.loads(json.loads(match.group()))
            else:
                await raise_for_status_body(resp)
                obj = await resp.json()
        for entry in obj["entries"]:
            yield entry["filename"], entry["is_dir"], entry["href"]
        if not obj["has_more_entries"]:
            break
        if method == "GET":
            method = "POST"
            url = "https://www.dropbox.com/list_shared_link_folder_entries"
            data = {
                "t": http_client.cookie_jar.filter_cookies(URL(url))["t"].value,
                "link_key": obj["folder_share_token"]["linkKey"],
                "link_type": obj["folder_share_token"]["linkType"],
                "secure_hash": obj["folder_share_token"]["secureHash"],
                "sub_path": obj["folder_share_token"]["subPath"],
            }
        assert data is not None
        data["voucher"] = obj["next_request_voucher"]


async def walk_shared_folder(
    http_client: aiohttp.ClientSession, url: str
) -> AsyncGenerator[Tuple[str, List[Tuple[str, str]], List[Tuple[str, str]]], None]:
    """
    Walk a Dropbox shared folder, similar to os.walk(). Generates path, list of
    files and their shared links, and list of folders and their shared links.
    """
    stack = [("", url)]
    while stack:
        path, url = stack.pop()
        dirs = []
        files = []
        async for filename, is_dir, href in list_shared_folder(http_client, url):
            if is_dir:
                dirs.append((filename, href))
            else:
                files.append((filename, href))
        yield path, files, dirs
        if path:
            path += "/"
        stack.extend((path + filename, href) for filename, href in dirs)


def make_download_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = [
        (name, value)
        for name, value in urllib.parse.parse_qsl(parsed.query)
        if name != "dl"
    ]
    query.append(("dl", "1"))
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))


async def update_index(
    http_client: aiohttp.ClientSession, token: str, uploader: Uploader
) -> bool:
    try:
        logger.info("finding shared folder link")
        headers = {"Authorization": "Bearer " + token}
        params = {
            "path": "/Public",
            "direct_only": True,
        }
        async with http_client.post(
            DROPBOX_API_URL + "/2/sharing/list_shared_links",
            headers=headers,
            json=params,
        ) as resp:
            await raise_for_status_body(resp)
            for link in (await resp.json())["links"]:
                if link[".tag"] != "folder":
                    continue
                try:
                    visibility = link["link_permissions"]["resolved_visibility"][".tag"]
                except KeyError:
                    continue
                if visibility == "public":
                    break
            else:
                raise Exception("shared folder link not found")

        logger.info("walking shared folder")
        async for path, files, dirs in walk_shared_folder(http_client, link["url"]):
            lines = []
            old_lines = []
            for name, href in files:
                href = make_download_url(href)
                lines.append(name + "\t" + href + "\n")
                if name == "INDEX":
                    async with http_client.get(href, raise_for_status=True) as resp:
                        old_lines = (await resp.text()).splitlines(keepends=True)
            lines.extend(name + "/\t" + href + "\n" for name, href in dirs)
            lines.sort()

            index_path = (path + "/" if path else "") + "INDEX"
            if lines == old_lines:
                logger.info("%s is up to date", index_path)
                continue
            diff = difflib.unified_diff(
                old_lines, lines, fromfile="a/" + index_path, tofile="b/" + index_path
            )
            logger.info("updating %s:\n%s", index_path, "".join(diff).rstrip("\n"))
            uploader.queue_file_obj(
                io.BytesIO("".join(lines).encode()),
                "/Public/" + index_path,
                mode="overwrite",
            )
        succeeded, failed = await uploader.wait()
        if failed:
            logger.info("updates failed: %s", ", ".join(failed))
            return False
        return True
    except Exception:
        logger.exception("updating INDEX files failed")
        return False


async def main() -> None:
    logging.basicConfig(
        format="%(asctime)s:%(levelname)s:%(name)s:%(message)s", level=logging.INFO
    )

    parser = argparse.ArgumentParser(
        description="Tool for managing drgn vmtest kernel builds and files"
    )
    parser.add_argument(
        "-b",
        "--build",
        type=str,
        action="append",
        metavar="COMMIT",
        help="build the given kernel release; may be given multiple times. "
        "Must be run from a Linux kernel git repository",
    )
    parser.add_argument(
        "-k",
        "--build-kernel-org",
        action="store_true",
        help="build new kernels listed on kernel.org",
    )
    parser.add_argument(
        "-u", "--upload", action="store_true", help="upload built kernels"
    )
    parser.add_argument(
        "-U",
        "--upload-file",
        type=str,
        action="append",
        dest="upload_files",
        metavar=("SRC_PATH", "DST_PATH"),
        nargs=2,
        help="upload the given file; may be given multiple times",
    )
    parser.add_argument(
        "-i", "--index", action="store_true", help="update the INDEX files"
    )
    args = parser.parse_args()

    if (args.build or args.build_kernel_org) and (
        not Path(".git").exists() or not Path("kernel").exists()
    ):
        sys.exit("-b/-k must be run from linux.git")

    if args.build_kernel_org or args.upload or args.upload_files or args.index:
        if os.isatty(sys.stdin.fileno()):
            dropbox_token = getpass.getpass("Enter Dropbox app API token: ")
        else:
            dropbox_token = input()

    builds_succeeded = []
    builds_failed = []
    uploads_succeeded = []
    uploads_failed = []

    async with aiohttp.ClientSession(trust_env=True) as http_client:
        # dict rather than set to preserve insertion order.
        to_build = dict.fromkeys(args.build or ())
        if args.build_kernel_org:
            localversion = get_current_localversion()
            logger.info("current localversion: %s", localversion)
            try:
                # In this context, "version" is a tag name without the "v"
                # prefix and "release" is a uname release string.
                logger.info(
                    "getting list of kernel.org versions and available releases"
                )
                kernel_org, available = await asyncio.gather(
                    get_kernel_org_versions(http_client),
                    get_available_kernel_releases(http_client, dropbox_token),
                )
                logger.info("kernel.org versions: %s", ", ".join(kernel_org))
                logger.info("available releases: %s", ", ".join(sorted(available)))
                for version in kernel_org:
                    match = re.fullmatch(r"(\d+\.\d+)(\.\d+)?(-rc\d+)?", version)
                    if not match:
                        logger.error("couldn't parse kernel.org version %r", version)
                        sys.exit(1)
                    release = "".join(
                        [
                            match.group(1),
                            match.group(2) or ".0",
                            match.group(3) or "",
                            localversion,
                        ]
                    )
                    if release not in available:
                        to_build["v" + version] = None
            except Exception:
                logger.exception(
                    "failed to get kernel.org releases and/or available releases"
                )
                sys.exit(1)

        if args.upload or args.upload_files or args.index:
            uploader = Uploader(http_client, dropbox_token)

        for src_path, dst_path in args.upload_files or ():
            uploader.queue_file(src_path, dst_path, autorename=False)

        if to_build:
            logger.info("releases to build: %s", ", ".join(to_build))
        for kernel in to_build:
            result = await try_build_kernel(kernel)
            if result is None:
                builds_failed.append(kernel)
                continue
            builds_succeeded.append(kernel)
            release, tarball = result
            if args.upload:
                uploader.queue_file(
                    str(tarball),
                    f"/Public/x86_64/kernel-{release}.tar.zst",
                    autorename=False,
                )

        if args.upload or args.upload_files:
            succeeded, failed = await uploader.wait()
            uploads_succeeded.extend(succeeded)
            uploads_failed.extend(failed)

        if builds_succeeded:
            logger.info("successfully built: %s", ", ".join(builds_succeeded))
        if builds_failed:
            logger.error("builds failed: %s", ", ".join(builds_failed))
        if uploads_succeeded:
            logger.info("successfully uploaded: %s", ", ".join(uploads_succeeded))
        if uploads_failed:
            logger.info("uploads failed: %s", ", ".join(uploads_failed))

        if builds_failed or uploads_failed:
            logger.error("builds and/or uploads failed; exiting")
            sys.exit(1)

        if args.index and not await update_index(http_client, dropbox_token, uploader):
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
