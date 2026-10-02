"""Deliberately unsafe process execution, used to prove the checks fire."""

import os
import subprocess


def run(command: str) -> int:
    os.system(command)
    subprocess.run(command, shell=True, check=False)
    return 0
