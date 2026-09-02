import re

text2 = """
def run_cmd(cmd):
  return os.popen(cmd).read()
"""

# Let's see if we just match `os.popen(cmd)` by adding os\.popen to the list and loosening the parameter requirement if it's a bare parameter (like `cmd`).
_U_broad = r"(?:req\.|request\.|\+|`[^`]*\$\{|f['\"]|%\s*[\(%]|\.format\s*\(|searchParams|nextUrl|params\[|[a-zA-Z_]\w*\s*(?:,|$|\)))"

regex = re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|os\.popen|subprocess\.(?:run|call|check_output|Popen))\s*\([^)]*"
        + _U_broad + r"|shell\s*=\s*True")

print("Regex text2:", regex.search(text2))
