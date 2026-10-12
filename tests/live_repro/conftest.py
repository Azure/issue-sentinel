import sys
from pathlib import Path

# The trusted runner scripts are plain modules, imported by file name.
SCRIPTS = Path(__file__).resolve().parents[2] / ".github" / "scripts" / "live_repro"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
