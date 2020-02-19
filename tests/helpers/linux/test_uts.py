import os

from tests.helpers.linux import LinuxHelperTestCase


class TestUts(LinuxHelperTestCase):
    def test_uts_release(self):
        self.assertEqual(
            self.prog["UTS_RELEASE"].string_().decode(), os.uname().release,
        )
