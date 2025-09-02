#!/usr/bin/env python3

from drgn.commands import DEFAULT_COMMAND_NAMESPACE
from tests import TestCase


class CommandTestCase(TestCase):

    @staticmethod
    def run_command(source, **kwargs):
        return DEFAULT_COMMAND_NAMESPACE.run(None, source, globals={}, **kwargs)
