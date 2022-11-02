#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("max", type=int)
    args = parser.parse_args()

    for i in range(2, args.max + 1):
        print(
            f"#define PP_CAT{str(i) if i > 2 else ''}("
            + ", ".join(f"_{j}" for j in range(i))
            + f") PP_CAT_I{i}("
            + ", ".join(f"_{j}" for j in range(i))
            + ")"
        )
    print("/** @cond */")
    for i in range(2, args.max + 1):
        print(
            f"#define PP_CAT_I{i}("
            + ", ".join(f"_{j}" for j in range(i))
            + ") "
            + "##".join(f"_{j}" for j in range(i))
        )
    print("/** @endcond */")
