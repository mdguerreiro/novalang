"""Developer test utilities (not deployed)."""
import subprocess
import sys


def test_replay_fixture():
    fixture = sys.argv[1] if len(sys.argv) > 1 else "default"
    subprocess.run("replay-fixture " + fixture, shell=True, check=False)
