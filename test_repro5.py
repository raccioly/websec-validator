import re

text2 = """
def run_cmd(cmd):
  return os.popen(cmd).read()
"""

_U = r"(?:req\.|request\.)"
regex2 = re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|os\.popen|subprocess\.(?:run|call|check_output|Popen))\s*\([^)]*"
        + _U + r"|shell\s*=\s*True")

print("Regex 2:", regex2.search(text2))
