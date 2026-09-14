"""Trusted composite-action entry point; inputs are data and outputs name this attempt."""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import sys
import tempfile


def run(main=None) -> int:
    if main is None:
        from websec_validator.cli import main
    values = {key: os.environ.get("WEBSEC_INPUT_" + key.upper().replace("-", "_"), default)
              for key, default in (("path", "."), ("out", "websec-out"), ("scan", "false"),
                                   ("fail-on", ""), ("baseline", ""), ("require-complete", "true"), ("scanners", ""))}
    if any(any(c in value for c in "\r\n\0") for value in values.values()):
        print("websec action: multiline/NUL inputs unsupported", file=sys.stderr)
        return 2
    if any(values[key] not in {"true", "false"} for key in ("scan", "require-complete")):
        print("websec action: scan and require-complete must be true or false", file=sys.stderr)
        return 2
    args = ["run", values["path"], "--out", values["out"], "--format", "json"]
    for key in ("scan", "require-complete"):
        if values[key] == "true":
            args.append("--" + key)
    for key in ("fail-on", "baseline", "scanners"):
        if values[key]:
            args.extend(["--" + key, values[key]])
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as capture:
        with contextlib.redirect_stdout(capture):
            rc = main(args)
        capture.seek(0)
        content = capture.read(64 * 1024 * 1024 + 1)
    try:
        if len(content) > 64 * 1024 * 1024:
            raise ValueError("machine envelope exceeds action limit")
        envelope = json.loads(content)
        name = envelope["generated"]
        if not isinstance(name, str) or Path(name).name != name or name in {".", ".."}:
            raise ValueError("invalid run identity")
        base = Path(values["out"]).expanduser().resolve()
        attempt = base / "runs" / name
        sarif = attempt / "results.sarif"
        if (attempt.is_symlink() or not attempt.resolve().is_relative_to(base)
                or not sarif.is_file() or sarif.is_symlink()):
            raise ValueError("current attempt SARIF unavailable")
        complete = (envelope.get("coverage") or {}).get("execution_complete") is True
        outputs = {"run_directory": str(attempt), "sarif_file": str(sarif),
                   "execution_complete": str(complete).lower(), "exit_code": str(rc)}
        if any("\n" in value or "\r" in value for value in outputs.values()):
            raise ValueError("artifact path cannot be represented as an action output")
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                for key, value in outputs.items():
                    stream.write(f"{key}={value}\n")
        print(f"websec action: exit {rc}; current attempt {attempt}; execution_complete={complete}")
        return rc
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"websec action: current artifact selection failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
