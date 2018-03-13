import argparse

import drgn.tool.dump


def main():
    parser = argparse.ArgumentParser(prog='drgntool')

    subparsers = parser.add_subparsers(
        title='command', description='command to run', dest='command')
    subparsers.required = True

    drgn.tool.dump.register(subparsers)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
