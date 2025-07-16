#!/usr/bin/env python3
"""Print all logged stack traces"""
from drgn.helpers.linux.printk import for_each_dmesg_stack_trace


for trace in for_each_dmesg_stack_trace(prog):
    print("[% 5d.%06d] CPU: %r PID: %r" % (
        trace.timestamp // 1000000000,
        trace.timestamp % 1000000000 // 1000,
        trace.cpu,
        trace.pid
    ))
    print(trace.stack_trace)
    print()
