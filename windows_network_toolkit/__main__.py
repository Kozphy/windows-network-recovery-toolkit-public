"""Package entrypoint for ``python -m windows_network_toolkit``.

Module responsibility:
    Delegates execution to ``windows_network_toolkit.cli.main``, passing the
    canonical program name so that argparse ``--help`` text displays
    ``windows_network_toolkit`` rather than the interpreter path.

System placement:
    Invoked when the user runs ``python -m windows_network_toolkit`` from a shell
    with ``PYTHONPATH`` set to the repository root.  Not imported by any other
    module.

Side effects:
    Calls ``sys.exit`` via ``raise SystemExit`` with the integer return code
    from ``cli.main``.
"""

from windows_network_toolkit.cli import main

if __name__ == "__main__":
    raise SystemExit(main(prog="windows_network_toolkit"))
