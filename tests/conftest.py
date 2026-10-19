import os
import shutil
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


IS_LINUX = sys.platform.startswith("linux")
IS_ROOT = IS_LINUX and os.geteuid() == 0
HAS_BPFTRACE = shutil.which("bpftrace") is not None

requires_linux = pytest.mark.skipif(not IS_LINUX, reason="requires Linux kernel interfaces")
requires_root = pytest.mark.skipif(not IS_ROOT, reason="requires root")
requires_ebpf = pytest.mark.skipif(not (IS_ROOT and HAS_BPFTRACE),
                                   reason="requires root + bpftrace")


def wait_for(predicate, timeout=10.0, interval=0.1):
    """Poll ``predicate`` until it returns a truthy value or ``timeout`` elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(interval)
    return predicate()
