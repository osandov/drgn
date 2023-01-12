# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
drgn entry point

This module runs the drgn CLI. There is nothing interesting here.

$ python3 -m drgn --help
"""


if __name__ == "__main__":
    from drgn.cli import _main

    _main()
