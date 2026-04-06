from __future__ import annotations

import os
import sys
from getpass import getpass
from typing import Optional, Sequence

IS_WINDOWS = sys.platform.startswith("win")
USE_COLOR = (not IS_WINDOWS) or bool(os.getenv("WT_SESSION")) or bool(os.getenv("TERM"))

if USE_COLOR:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
else:
    CYAN = GREEN = YELLOW = RED = BOLD = DIM = RESET = ""


def banner() -> None:
    print(
        f"""
{CYAN}{BOLD}+------------------------------------------------------------+
|                 WIFI STREAM PIPELINE v2.0                  |
|      Native Windows capture, flow extraction, analysis     |
+------------------------------------------------------------+{RESET}
""".rstrip()
    )


def section(title: str) -> None:
    rule = "-" * max(8, 60 - len(title))
    print(f"\n{CYAN}{BOLD}-- {title} {rule}{RESET}")


def ok(message: str) -> None:
    print(f"{GREEN}[+]{RESET} {message}")


def info(message: str) -> None:
    print(f"{CYAN}[*]{RESET} {message}")


def warn(message: str) -> None:
    print(f"{YELLOW}[!]{RESET} {message}")


def err(message: str) -> None:
    print(f"{RED}[x]{RESET} {message}")


def done(message: str) -> None:
    print(f"{GREEN}{BOLD}[ok]{RESET} {message}")


def ask(prompt: str, default: Optional[str] = None, secret: bool = False) -> str:
    suffix = f" [{default}]" if default is not None and not secret else ""
    rendered = f"{YELLOW}  >{RESET} {prompt}{suffix}: "
    try:
        value = getpass(rendered) if secret else input(rendered)
    except (KeyboardInterrupt, EOFError):
        print()
        return default or ""
    value = value.strip()
    if value:
        return value
    return default or ""


def ask_int(prompt: str, default: int) -> int:
    value = ask(prompt, str(default))
    try:
        return int(value)
    except ValueError:
        warn(f"Invalid integer: {value!r}. Keeping {default}.")
        return default


def confirm(prompt: str, default: bool = True) -> bool:
    options = "Y/n" if default else "y/N"
    try:
        value = input(f"{YELLOW}  >{RESET} {prompt} [{options}]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        return default
    if not value:
        return default
    return value.startswith("y")


def choose(prompt: str, options: Sequence[str], default: int = 0) -> int:
    print(f"\n{YELLOW}  {prompt}{RESET}")
    for index, option in enumerate(options):
        marker = f"{GREEN}>{RESET}" if index == default else " "
        print(f"  {marker} [{index + 1}] {option}")
    try:
        raw = input(f"{YELLOW}  >{RESET} Choice [{default + 1}]: ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return default
    if not raw:
        return default
    try:
        selected = int(raw) - 1
    except ValueError:
        return default
    return max(0, min(selected, len(options) - 1))
