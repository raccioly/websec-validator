import re

text2 = """
def run_cmd(cmd):
  return os.popen(cmd).read()
"""

# Let's see if we just match `os.popen(cmd)` without requiring `req.` or `request.`
# Wait, `cmd` is untrusted here? Not necessarily from `req.`, but it's a function parameter.
regex3 = re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|os\.popen|subprocess\.(?:run|call|check_output|Popen))\s*\([^)]*"
        + r"(?:req\.|request\.|cmd)" + r"|shell\s*=\s*True")

print("Regex 3:", regex3.search(text2))
