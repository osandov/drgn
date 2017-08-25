import argparse

import drgn.cli.dump
import drgn.cli.probe


def main():
    parser = argparse.ArgumentParser(prog='drgn')

    subparsers = parser.add_subparsers(
        title='command', description='command to run', dest='command')
    subparsers.required = True

    drgn.cli.dump.register(subparsers)
    drgn.cli.probe.register(subparsers)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
