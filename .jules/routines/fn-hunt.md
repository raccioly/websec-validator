# Routine: fn-hunt (weekly, Wednesday)

Find realistic code shapes where a sink class is genuinely exploitable but websec reports nothing,
and fix the detector for them without adding false positives. A missed detection is the most
expensive defect a security tool has: the run reads as clean.

Follow `.jules/RULES.md` throughout.

## Steps

1. Run `python .jules/preflight.py fn-hunt`. On STOP, end the task. On GO, the `target:` line is
   the one sink class you hunt (for example `command-injection`).
2. Read how the class is detected today: its entry in `SINKS` in
   `src/websec_validator/extractors/surface.py`, the user-input gate `_U` it relies on, and the
   class's section in `docs/METHODOLOGY.md`.
3. In a temporary directory **outside the repository**, write 6–10 small, realistic variants where
   attacker-controlled input reaches that sink. Cover Python and JavaScript/TypeScript, and the
   shapes regexes miss:
   - input passed through a function parameter (`def run(cmd): os.popen(cmd)` called with
     `request.args["c"]`);
   - an alias or intermediate variable; an f-string or template literal; keyword arguments;
   - a thin wrapper (`def sh(c): subprocess.run(c, shell=True)`);
   - the framework's own request object (Flask, FastAPI, Django, Express, Next.js route handlers).
4. Scan it:

   ```bash
   python -m websec_validator run <tmpdir> --out <tmpdir>/out
   ```

   A miss is a variant with no finding of the target class in `<tmpdir>/out/latest/findings-ledger.json`.
5. For each miss, confirm by reading the code path that the input really is attacker-controlled
   and really reaches the sink. Drop it (list it under **Dropped**) if it is not exploitable, or if
   detecting it would need whole-program data flow, which is out of model (see
   `docs/reference/languages.md`).
6. If nothing is left, end the task with no pull request. The summary lists the variants you tried.
7. For up to three confirmed misses, in one new file `tests/test_jules_fn_hunt_<target>.py` (`-` written as `_`):
   - a test with the vulnerable variant that **fails** on `main`;
   - for each, a paired safe variant (constant argument, allowlisted value, parameterised API)
     that must stay quiet.
8. Make the smallest change under `src/websec_validator/extractors/` that makes the new tests pass
   with every existing test still passing. Never loosen the user-input gate globally: a fix that
   detects your variants by also flagging constant arguments is a false-positive regression.
9. Run the checks in `.jules/RULES.md` §4, then open the pull request with the preflight title,
   for example `[jules:fn-hunt] command-injection — parameter-passed os.popen`.

A change under `src/` always waits for maintainer review. That is expected.
