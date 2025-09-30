import os
from typing import List

def generate_taskkill_commands(pids: List[int]) -> List[str]:
    commands = []
    for pid in pids:
        commands.append(f"taskkill /PID {pid} /F")
    return commands

def generate_quarantine_instructions(dumped_files: List[str], quarantine_dir: str = "quarantine"):
    os.makedirs(quarantine_dir, exist_ok=True)
    instructions = []
    for f in dumped_files:
        base = os.path.basename(f)
        target = os.path.join(quarantine_dir, base)
        instructions.append(f"mv \"{f}\" \"{target}\"  # move to quarantine")
    return instructions
