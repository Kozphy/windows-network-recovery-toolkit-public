"""Enable ``python -m platform_core.replay`` invocation."""

from __future__ import annotations

import sys

from platform_core.replay.runner import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
