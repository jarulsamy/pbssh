"""CLI Entrypoint."""

import sys
from .pbssh import main

if __name__ == "__main__":
    sys.exit(main())