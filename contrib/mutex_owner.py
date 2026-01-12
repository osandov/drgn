#!/usr/bin/env drgn
# Copyright (c) Cloudflare
# SPDX-License-Identifier: LGPL-2.1-or-later

"""List the task holding a mutex and which tasks are waiting."""

import sys
import drgn
from drgn import FaultError, NULL, Object, cast, container_of, execscript, offsetof, reinterpret, sizeof, stack_trace
from drgn.helpers.common import *
from drgn.helpers.linux import *

def main(mutex_name):
	print("Mutex details for '%s'" % mutex_name)
	print("="*40)

	m = prog[mutex_name]
	t = mutex_owner(m)
	if t:
		owner = "{}-{}".format(t.comm.string_().decode(), int(t.pid))
		print("\tOwner: {}".format(owner))
		for e in stack_trace(t):
			print("\t\t{}".format(e))
	else:
		print("\tOwner: none")

	print("\tWaiters:")
	for waiter in list_for_each(m.wait_list.address_of_()):
		t = container_of(waiter, prog.type('struct mutex_waiter'), 'list').task
		print("\t\t{}-{}".format(t.comm.string_().decode(), int(t.pid)))
		for e in stack_trace(t):
			print("\t\t\t{}".format(e))

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print("Usage: %s <mutex name>" % (sys.argv[0]))
		sys.exit(1)

	main(sys.argv[1])
