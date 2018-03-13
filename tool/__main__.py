import argparse

from . import dump


def main():
    parser = argparse.ArgumentParser(prog='drgntool')

    subparsers = parser.add_subparsers(
        title='command', description='command to run', dest='command')
    subparsers.required = True

    dump.register(subparsers)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
