"""Allow running as ``python -m incogni``."""

from incogni.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
