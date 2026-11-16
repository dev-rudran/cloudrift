"""Enable ``python -m cloudrift``."""

from __future__ import annotations

import sys

from cloudrift.cli import main

if __name__ == "__main__":
    sys.exit(main())
