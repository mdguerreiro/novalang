"""Process helpers."""
import subprocess


def run_cmd(args):
    return subprocess.run(args, capture_output=True, check=False)


def run_shell(command):
    return subprocess.run(command, shell=True, capture_output=True, check=False)
