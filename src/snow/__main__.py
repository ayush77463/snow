"""Direct package execution entry point for SNOW (`python -m snow`)."""

import sys
from snow.main import main

if __name__ == "__main__":
    sys.exit(main())
