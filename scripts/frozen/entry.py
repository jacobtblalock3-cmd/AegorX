"""Frozen-binary entry point: mirrors the `aegorx` console script."""

import sys


def main() -> int:
    from aegorx.cli import main as cli_main

    return cli_main(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
