import re
_U = r"(?:req\.|request\.|\+|`[^`]*\$\{|f['\"]|%\s*[\(%]|\.format\s*\(|searchParams|nextUrl|params\[)"

text2 = """
def run_cmd(cmd):
  return os.popen(cmd).read()
"""

# Try without modifying _U, but using a simpler fallback for os.popen. Or maybe just adding `os.popen` to the main list is enough if `_U` doesn't strictly require string formatting? Wait, `_U` is `req.|request.|\+|...`. Since `os.popen(cmd)` has no string formatting (`+`, `f""`, `%`), `_U` won't match unless we modify `_U`.
# However, `os.popen` executes a shell command, so ANY argument to `os.popen` that isn't a hardcoded string literal could be a command injection.
regex = re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|os\.popen|subprocess\.(?:run|call|check_output|Popen))\s*\(\s*(?!['\"]).*"
        + r"|shell\s*=\s*True")

print("Regex text2:", regex.search(text2))
