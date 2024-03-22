# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse

from tests.resources import get_resource

parser = argparse.ArgumentParser(
    description="decompress test resources and print their paths"
)
parser.add_argument("name", nargs="+", help="resource name")
args = parser.parse_args()

for name in args.name:
    print(get_resource(name))
