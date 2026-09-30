"""Git metadata reads must not execute helpers selected by the inspected checkout."""
from __future__ import annotations

import os
import subprocess


def run(target, *args: str, timeout: int = 20):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    command = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
               "-c", "core.pager=cat", "-c", "log.showSignature=false",
               "-c", "gpg.program=" + os.devnull, "-c", "gpg.openpgp.program=" + os.devnull,
               "-c", "gpg.x509.program=" + os.devnull, "-c", "gpg.ssh.program=" + os.devnull,
               "-C", str(target)]
    if "status" in args or "diff" in args:
        # Status may rehash dirty files through clean/process filters from .gitattributes.
        # Read names (not commands) via a non-executing config query, then override every driver.
        filters = subprocess.run([*command, "config", "--null", "--name-only", "--get-regexp",
                                  r"^filter\..*\.(clean|smudge|process|required)$"],
                                 env=env, capture_output=True, text=True, timeout=timeout)
        if filters.returncode not in (0, 1) or len(filters.stdout) > 1_000_000:
            raise OSError("cannot isolate checkout filter configuration")
        for key in filters.stdout.split("\0"):
            if key:
                if not key.startswith("filter.") or key.rsplit(".", 1)[-1] not in {"clean", "smudge", "process", "required"}:
                    raise OSError("invalid checkout filter configuration")
                command.extend(("-c", key + ("=false" if key.endswith(".required") else "=")))
    command.extend(args)
    return subprocess.run(command, env=env, capture_output=True, text=True, timeout=timeout)
