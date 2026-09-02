import re

_U = r"(?:req\.|request\.|\+|`[^`]*\$\{|f['\"]|%\s*[\(%]|\.format\s*\(|searchParams|nextUrl|params\[)"

# Current
regex_current = re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|subprocess\.(?:run|call|check_output|Popen))\s*\([^)]*"
        + _U + r"|shell\s*=\s*True")

# Proposed
regex_proposed = re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|os\.popen|subprocess\.(?:run|call|check_output|Popen))\s*\([^)]*"
        + _U + r"|os\.(?:system|popen)\s*\(\s*(?!['\"])[a-zA-Z_]\w*|shell\s*=\s*True")

print(regex_proposed.search("subprocess.run(args, shell=True)"))
print(regex_proposed.search("os.system(cmd)"))
print(regex_proposed.search("os.popen(request.body)"))
print(regex_proposed.search("os.popen('ls -l')"))
