"""
state_manager.py

Purpose
-------
Manages the monitoring state for the Intelligent SOC Assistant.

The module stores the last successfully processed Windows Event
Record ID for each monitored Windows Event Log channel.

Why this is required
--------------------
When the SOC Assistant is restarted, it should continue from the
last processed event instead of unnecessarily processing old events
again.

Example stored state
--------------------
{
    "Security": 18503,
    "System": 9032,
    "Microsoft-Windows-PowerShell/Operational": 421
}

The state is stored in:

    state/last_record.txt
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from threading import Lock
from typing import Dict


# ==========================================================
# Thread Lock
# ==========================================================

# Later, the desktop application may have monitoring running
# in a background thread while the GUI is running.
#
# This lock prevents two parts of the application from writing
# the state file at exactly the same time.

_STATE_LOCK = Lock()


# ==========================================================
# Base Directory
# ==========================================================

def get_base_directory() -> Path:
    """
    Return the base directory used for writable application data.

    Normal Python execution:
        Returns the project root.

    PyInstaller executable:
        Returns the directory containing the .exe file.

    This allows the same state-management logic to work during
    development and after packaging the project as a Windows EXE.
    """

    if getattr(sys, "frozen", False):

        return Path(
            sys.executable
        ).resolve().parent

    return Path(
        __file__
    ).resolve().parent.parent


BASE_DIR = get_base_directory()

STATE_DIR = BASE_DIR / "state"

STATE_FILE = STATE_DIR / "last_record.txt"


# ==========================================================
# State Initialization
# ==========================================================

def ensure_state_file() -> None:
    """
    Ensure that the state directory and state file exist.

    If they do not exist, they are created automatically.
    """

    STATE_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    if not STATE_FILE.exists():

        STATE_FILE.write_text(
            "{}",
            encoding="utf-8"
        )


# ==========================================================
# Load Complete State
# ==========================================================

def load_state() -> Dict[str, int]:
    """
    Load all saved Windows Event Log record IDs.

    Returns
    -------
    Dict[str, int]

    Example
    -------
    {
        "Security": 18503,
        "System": 9032
    }

    If the state file is empty, missing, or invalid,
    an empty dictionary is returned safely.
    """

    ensure_state_file()

    try:

        content = STATE_FILE.read_text(
            encoding="utf-8"
        ).strip()

        if not content:

            return {}

        data = json.loads(
            content
        )

        if not isinstance(
            data,
            dict
        ):

            return {}

        clean_state: Dict[str, int] = {}

        for channel, record_id in data.items():

            try:

                clean_state[
                    str(channel)
                ] = int(
                    record_id
                )

            except (
                TypeError,
                ValueError
            ):

                # Ignore invalid entries instead of crashing
                # the entire monitoring application.

                continue

        return clean_state

    except (
        OSError,
        json.JSONDecodeError
    ):

        return {}


# ==========================================================
# Save Complete State
# ==========================================================

def save_state(
    state: Dict[str, int]
) -> bool:
    """
    Save the complete monitoring state.

    A temporary file is written first and then replaces the
    actual state file.

    This reduces the chance of leaving a partially written
    state file if writing is interrupted.

    Returns
    -------
    bool

        True  -> State saved successfully
        False -> State could not be saved
    """

    ensure_state_file()

    temporary_file = STATE_FILE.with_suffix(
        ".tmp"
    )

    try:

        clean_state = {

            str(channel): int(record_id)

            for channel, record_id
            in state.items()
        }

        with _STATE_LOCK:

            temporary_file.write_text(

                json.dumps(
                    clean_state,
                    indent=4
                ),

                encoding="utf-8"
            )

            temporary_file.replace(
                STATE_FILE
            )

        return True

    except (
        OSError,
        TypeError,
        ValueError
    ):

        return False


# ==========================================================
# Get Last Record
# ==========================================================

def get_last_record(
    channel: str = "Security"
) -> int:
    """
    Return the last processed Event Record ID for a channel.

    Parameters
    ----------
    channel : str

        Windows Event Log channel.

        Example:
            Security

    Returns
    -------
    int

        Last stored record ID.

        Returns 0 when no record has been stored.
    """

    if not channel:

        return 0

    state = load_state()

    try:

        return int(

            state.get(
                channel,
                0
            )

        )

    except (
        TypeError,
        ValueError
    ):

        return 0


# ==========================================================
# Save Last Record
# ==========================================================

def save_last_record(
    record_id: int,
    channel: str = "Security"
) -> bool:
    """
    Save the latest successfully processed Event Record ID
    for one Windows Event Log channel.

    The stored record number is normally allowed to move only
    forward.

    Parameters
    ----------
    record_id : int

        Windows Event Record ID.

    channel : str

        Windows Event Log channel.

    Returns
    -------
    bool

        True  -> Saved successfully
        False -> Invalid data or write failure
    """

    if not channel:

        return False

    try:

        record_id = int(
            record_id
        )

    except (
        TypeError,
        ValueError
    ):

        return False

    if record_id < 0:

        return False

    state = load_state()

    try:

        current_record = int(

            state.get(
                channel,
                0
            )

        )

    except (
        TypeError,
        ValueError
    ):

        current_record = 0

    # Do not move the saved position backwards.
    #
    # Example:
    #
    # Current = 500
    # New     = 450
    #
    # Keep 500.

    if record_id < current_record:

        return True

    state[
        channel
    ] = record_id

    return save_state(
        state
    )


# ==========================================================
# Reset One Channel
# ==========================================================

def reset_channel(
    channel: str
) -> bool:
    """
    Remove the saved record position for one channel.

    This is mainly useful during controlled testing.
    """

    if not channel:

        return False

    state = load_state()

    state.pop(
        channel,
        None
    )

    return save_state(
        state
    )


# ==========================================================
# Reset Complete State
# ==========================================================

def reset_state() -> bool:
    """
    Reset all saved Windows Event Log positions.

    Intended mainly for development/testing.

    After resetting:

        state/last_record.txt

    will contain:

        {}
    """

    return save_state(
        {}
    )


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    print(
        "=========================================="
    )

    print(
        " Intelligent SOC Assistant"
    )

    print(
        " State Manager Test"
    )

    print(
        "=========================================="
    )

    print()

    print(
        f"State file: {STATE_FILE}"
    )

    print()

    print(
        "Current state:"
    )

    print(
        load_state()
    )

    print()

    print(
        "Last Security record:"
    )

    print(
        get_last_record(
            "Security"
        )
    )

    print()

    print(
        "State manager is working."
    )