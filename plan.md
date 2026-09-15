1. **Submit the PR**
   - The user requested me to verify the Docker build, scanner execution, and deduplication logic, and fix any issues found in a PR.
   - I have verified the Docker build (`docker build -t websec-validator .`).
   - I verified all bundled scanners were detected (`docker run --rm websec-validator doctor`).
   - I verified the merge logic output against VAmPI with scanner enabled vs disabled.
   - I encountered two issues that caused the scan to be incomplete:
     - Trivy failed to download in the docker build because the 0.58.1 tag was missing from GitHub. I updated it to 0.74.0 which successfully installed.
     - Semgrep output contained JSON with a `errors` array containing warnings about bash scripts syntax (`PartialParsing`). The existing script in `scanners.py` failed the entire Semgrep scan if any errors were found (`row.get("errors")`), regardless of the error severity (warnings vs fatal errors). I updated it to ignore warnings from Semgrep.
   - I have successfully tested `python3 -m unittest discover -s tests`, `python3 -m compileall -q src`, and `docguard guard`.
   - The final step is to submit the commit to the branch using `submit`.
