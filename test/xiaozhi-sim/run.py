"""CLI for the self-contained CI-only harness; outputs safe summary JSON."""
import json
from pathlib import Path
import sys
import unittest

from harness import UPSTREAM_SHA, credential_guard


def main():
    credential_guard()
    suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=1, stream=sys.stderr).run(suite)
    report = {
        "schema": "mctl.desk.protocol-sim/v1",
        "upstream_sha": UPSTREAM_SHA,
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "verdict": "protocol_compatible_sim" if result.wasSuccessful() else "incompatible",
    }
    # Structural allowlist: never emit transcript, audio or tokens.
    assert set(report) == {"schema", "upstream_sha", "tests", "failures", "errors", "verdict"}
    print(json.dumps(report, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())