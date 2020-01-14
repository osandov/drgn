import os
import os.path

from drgn.helpers.linux.block import (
    disk_devt,
    disk_name,
    for_each_disk,
    for_each_partition,
    part_devt,
    part_name,
)
from drgn.helpers.linux.device import MAJOR, MINOR
from tests.helpers.linux import LinuxHelperTestCase


class TestBlock(LinuxHelperTestCase):
    def test_disk_devt(self):
        for disk in for_each_disk(self.prog):
            path = os.path.join(b"/sys/block", disk_name(disk), b"dev")
            with open(path, "r") as f:
                expected = f.read().strip()
            devt = disk_devt(disk).value_()
            self.assertEqual(f"{MAJOR(devt)}:{MINOR(devt)}", expected)

    def test_for_each_disk(self):
        self.assertEqual(
            set(os.listdir("/sys/block")),
            {disk_name(disk).decode() for disk in for_each_disk(self.prog)},
        )

    def test_part_devt(self):
        for part in for_each_partition(self.prog):
            path = os.path.join(b"/sys/class/block", part_name(part), b"dev")
            with open(path, "r") as f:
                expected = f.read().strip()
            devt = part_devt(part).value_()
            self.assertEqual(f"{MAJOR(devt)}:{MINOR(devt)}", expected)

    def test_for_each_part(self):
        self.assertEqual(
            set(os.listdir("/sys/class/block")),
            {part_name(part).decode() for part in for_each_partition(self.prog)},
        )
