# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Internal utilities for drgn

This package contains utilities shared between the drgn package and supporting
build/test code. You should not use them.

This package must not depend on the drgn package itself since it is used before
the _drgn extension module is built.
"""
