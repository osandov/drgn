import os
import os.path


TRACEFS = '/sys/kernel/debug/tracing'


def write_tracefs(path, contents):
    fd = os.open(os.path.join(TRACEFS, path), os.O_WRONLY)
    try:
        n = os.write(fd, contents)
        assert n == len(contents)
    finally:
        os.close(fd)


def append_tracefs(path, contents):
    fd = os.open(os.path.join(TRACEFS, path), os.O_WRONLY | os.O_APPEND)
    try:
        n = os.write(fd, contents)
        assert n == len(contents)
    finally:
        os.close(fd)


class _Probe:
    def __init__(self, probe_name):
        self.probe_name = probe_name

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        s = f'-:{self.probe_name}\n'
        append_tracefs('kprobe_events', s.encode())

    def enable(self, instance=None):
        if instance is None:
            write_tracefs(f'events/{self.probe_name}/enable', b'1')
        else:
            write_tracefs(f'instances/{instance.name}/events/{self.probe_name}/enable', b'1')

    def disable(self, instance=None):
        if instance is None:
            write_tracefs(f'events/{self.probe_name}/enable', b'0')
        else:
            write_tracefs(f'instances/{instance.name}/events/{self.probe_name}/enable', b'0')


class Kprobe(_Probe):
    def __init__(self, probe_name, location, fetchargs=None):
        super().__init__(probe_name)
        self.location = location
        if fetchargs is None:
            self.fetchargs = ''
        else:
            self.fetchargs = ' '.join(fetchargs)

    def __enter__(self):
        s = f'p:{self.probe_name} {self.location} {self.fetchargs}\n'
        append_tracefs('kprobe_events', s.encode())
        return self


class FtraceInstance:
    def __init__(self, name):
        self.name = name

    def __enter__(self):
        os.mkdir(f'{TRACEFS}/instances/{self.name}')
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        os.rmdir(f'{TRACEFS}/instances/{self.name}')
