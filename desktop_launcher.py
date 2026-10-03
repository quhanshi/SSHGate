"""PyInstaller entry point. Runtime assets are read from the bundled resource root."""
from ssh_gate.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
