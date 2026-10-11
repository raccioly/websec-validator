# Routine: fp-hunt (weekly, Monday)

Find realistic safe code that one extractor reports as a vulnerability, and fix the extractor so
it stays quiet on that code while every real vulnerability of the same shape still fires.

Follow `.jules/RULES.md` throughout.

## Steps

1. Run `python3 .jules/preflight.py fp-hunt`. On STOP, end the task. On GO, the `target:` line is
   the one extractor you hunt (for example `crypto_usage`).
2. Read the extractor (`src/websec_validator/extractors/<target>.py`) and the tests that already pin
   it (`grep -rn "<ExtractorClass>" tests/`). List the patterns it matches.
3. Check what was already tried: search closed pull requests for the extractor's file name. If a
   pattern you are about to "fix" was proposed and declined, drop it — the maintainer's reason is
   in that PR's comments.
4. In a temporary directory **outside the repository**, write 6–10 small, realistic **safe**
   programs that resemble what the extractor matches: the sanitised value, the constant argument,
   the hash of a nonce rather than a password, the validated redirect, test-only code.
5. Scan it:

   ```bash
   websec run <tmpdir> --out <tmpdir>/out
   ```

   A false positive is a finding from the target extractor on code that is not vulnerable. Confirm
   each one by reasoning about the code, not by its name: a variable called `safe` is not evidence.
6. If nothing is left, end the task with no pull request. The summary lists the programs you tried.
7. For up to three confirmed false positives, in one new file
   `tests/test_jules_fp_hunt_<target>.py`, write **pairs**:
   - the safe program, asserting no finding of that kind — it fails on `main`;
   - the nearest genuinely vulnerable program, asserting the finding still fires. This is the
     negative control; without it the fix can hide real vulnerabilities, and the PR is held.
8. Make the smallest change in the extractor that makes both halves of every pair pass, with every
   existing test still passing. Prefer narrowing on evidence (the argument is a literal, the value
   came from a randomness API) over excluding names.
9. Run the checks in `.jules/RULES.md` §4, then open the pull request with the preflight title,
   for example `[jules:fp-hunt] crypto_usage — nonce hashed with md5`.

A change under `src/` always waits for maintainer review. That is expected.
