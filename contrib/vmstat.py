#!/usr/bin/env drgn
# Copyright (c) SUSE Linux.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Dump /proc/vmstat statistics."""

from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.percpu import per_cpu


def print_event_line(event, counter):
    print(f"{event.name:<36} {counter.value_():>16}")


print(f"{'Event':<36} {'Count':>16}")

# For all of the below, we skip the last enumerator item as it holds the number
# of enumerators.

# 1) vm_zone_stat statistics are there since v4.8.
if "vm_zone_stat" in prog:
    print("VM_ZONE_STAT:")
    vm_zone_stat = prog["vm_zone_stat"]
    for event in prog.type("enum zone_stat_item").enumerators[:-1]:
        print_event_line(event, vm_zone_stat[event.value].counter)
    print()

# 2) vm_node_stat statistics are there since v4.8.
if "vm_node_stat" in prog:
    print("VM_NODE_STAT:")
    vm_node_stat = prog["vm_node_stat"]
    for event in prog.type("enum node_stat_item").enumerators[:-1]:
        print_event_line(event, vm_node_stat[event.value].counter)
    print()

# 3) vm_numa_event statistics are there since v5.14. They are only populated if
# CONFIG_NUMA is enabled.
if "node_subsys" in prog and "vm_numa_event" in prog:
    print("VM_NUMA_EVENT:")
    vm_numa_event = prog["vm_numa_event"]
    for event in prog.type("enum numa_stat_item").enumerators[:-1]:
        print_event_line(event, vm_numa_event[event.value].counter)
    print()

# 4) vm_event_states statistics (uses per-CPU counters)
print("VM_EVENT_STATES:")
vm_event_states = prog["vm_event_states"]
cpulist = list(for_each_online_cpu(prog))
for event in prog.type("enum vm_event_item").enumerators[:-1]:
    count = sum([per_cpu(vm_event_states, cpu).event[event.value] for cpu in cpulist])
    print_event_line(event, count)
