import re
_U = r"(?:req\.|request\.)"

regex = re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|os\.popen|subprocess\.(?:run|call|check_output|Popen))\s*\([^)]*")

text3 = """
def run_cmd(cmd):
  return os.popen(cmd).read()
"""

print("Regex 3:", regex.search(text3))
