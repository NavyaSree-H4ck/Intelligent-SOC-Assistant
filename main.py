"""
main.py

Main entry point for the Intelligent SOC Assistant
desktop application.

This file will also become the entry point used by
PyInstaller when the final Windows EXE is created.
"""

import sys

from dashboard.dashboard import (
    run_desktop_application,
)


def main() -> int:
    """
    Start the Intelligent SOC Assistant.
    """

    return run_desktop_application()


if __name__ == "__main__":

    sys.exit(
        main()
    )