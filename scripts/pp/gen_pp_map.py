#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("max", type=int)
    args = parser.parse_args()

    print(
        "#define PP_MAP(func, arg, ...) PP_OVERLOAD(PP_MAP_I, __VA_ARGS__)(func, arg, __VA_ARGS__)"
    )
    print("/** @cond */")
    for i in range(args.max, 1, -1):
        print(
            f"#define PP_MAP_I{i}(func, arg, x, ...) func(arg, x) PP_MAP_I{i - 1}(func, arg, __VA_ARGS__)"
        )
    print("#define PP_MAP_I1(func, arg, x) func(arg, x)")
    print("#define PP_MAP_I0(func, arg, x)")
    print("/** @endcond */")
