# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
drgn entry point

This module runs the drgn CLI. There is nothing interesting here.

$ python3 -m drgn --help
"""


if __name__ == "__main__":
    from drgn.internal.cli import main

    main()
