import re

# Adding os.popen and loosening the required input to just "not immediately closed or an empty string" or just adding os.popen
text = """
def run_cmd(cmd):
  return os.popen(cmd).read()
"""

# Current regex
_U = r"(?:req\.|request\.|\+|`[^`]*\$\{|f['\"]|%\s*[\(%]|\.format\s*\(|searchParams|nextUrl|params\[)"
old_regex = re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|subprocess\.(?:run|call|check_output|Popen))\s*\([^)]*"
        + _U + r"|shell\s*=\s*True")

# If we expand to include `os.popen`:
new_regex = re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|os\.popen|subprocess\.(?:run|call|check_output|Popen))\s*\([^)]*"
        + r"(?:" + _U + r"|[a-zA-Z_]\w*\s*(?:,|$|\)))" + r"|shell\s*=\s*True")

# wait, if we allow `[a-zA-Z_]\w*\s*(?:,|$|\))`, it will match `os.popen(cmd)`. But it will also match `subprocess.run(args)` which might not be a string and usually is safe if shell=False. But `os.popen` is implicitly shell=True!
# So maybe we just treat `os.popen` and `os.system` as implicitly dangerous unless the argument is a literal string, but wait: `os.system("ls")` is safe, `os.system(cmd)` is dangerous.
# Since `os.system` and `os.popen` always invoke a shell, ANY variable argument is a command injection risk (unlike `subprocess.run` where a list is safe).

# Let's see:
regex_explicit_shell = re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|os\.popen|subprocess\.(?:run|call|check_output|Popen))\s*\([^)]*"
        + _U + r"|os\.(?:system|popen)\s*\(\s*(?!['\"])[a-zA-Z_]\w*|shell\s*=\s*True")

print("Match:", regex_explicit_shell.search(text))
