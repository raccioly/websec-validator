import re
_U = r"(?:req\.|request\.|\+|`[^`]*\$\{|f['\"]|%\s*[\(%]|\.format\s*\(|searchParams|nextUrl|params\[)"

text = """
  def mutate(self, info, host='pastebin.com', port=443, path='/', scheme="http"):
    url = security.strip_dangerous_characters(f"{scheme}://{host}:{port}{path}")
    cmd = helpers.run_cmd(f'curl --insecure {url}')
"""

# The run_cmd isn't being detected as a command-injection sink because run_cmd is an app-specific wrapper,
# not one of the built-in python exec functions, but what about the actual os.popen call?
text2 = """
def run_cmd(cmd):
  return os.popen(cmd).read()
"""

# It doesn't use formatting, it just passes `cmd` variable directly. But is there another way to catch `os.popen`?
regex = re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|os\.popen|subprocess\.(?:run|call|check_output|Popen))\s*\([^)]*"
        + _U + r"|shell\s*=\s*True")

print("Regex text:", regex.search(text))
print("Regex text2:", regex.search(text2))

# What if we just add os.popen to the list and rely on the existing _U? It won't match `os.popen(cmd)`.
