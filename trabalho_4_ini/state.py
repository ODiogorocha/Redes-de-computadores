import json
import threading
import time
from pathlib import Path


STATE_FILE = Path("state.json")

_lock = threading.Lock()


def save(state):

    with _lock:

        state["timestamp"] = time.time()

        with open(STATE_FILE, "w") as f:

            json.dump(state, f, indent=4)


def load():

    if not STATE_FILE.exists():

        return {}

    with _lock:

        with open(STATE_FILE) as f:

            return json.load(f)