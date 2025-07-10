#!/usr/bin/env drgn
# Copyright (c) 2025, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import sys
import argparse
from drgn.helpers.linux import find_task
from drgn import stack_trace

def main():
    parser = argparse.ArgumentParser(description="Show stack trace and optionally local variables of a specific frame")
    parser.add_argument("pid", type=int, help="Target process PID")
    parser.add_argument("frameid", type=int, nargs="?", help="Stack frame index (optional)")
    args = parser.parse_args()

    task = find_task(args.pid)
    print(f"PID {args.pid} process name: {task.comm.string_().decode(errors='replace')}")
    trace = stack_trace(task)
    print(trace)
    if args.frameid is not None:
        frame = trace[int(args.frameid)]
        print(frame)
        locals_ = frame.locals()
        print(locals_)
        for var in locals_:
            try:
                value = frame[var]
                print(f"{var}: {value}")
            except KeyError:
                print(f"{var}: Not found")

if __name__ == "__main__":
    main()
