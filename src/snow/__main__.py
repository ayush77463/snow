"""Direct package execution entry point for SNOW (`python -m snow`)."""

import sys


def entry_point() -> int:
    """Intelligent CLI entry point dispatch.

    - Zero arguments: Preserves default behavior, launching the SNOW Desktop Core server.
    - Subcommand or flags provided: Dispatches directly to the SNOW CLI parser (`snow.cli.main`),
      preventing accidental second Core server instances and port 8765 collisions.
    """
    args = sys.argv[1:]
    if not args:
        from snow.main import main as core_main
        return core_main()

    from snow.cli import main as cli_main
    return cli_main(args)


if __name__ == "__main__":
    sys.exit(entry_point())
