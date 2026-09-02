import re

text = """
def mutate(self, info, host='pastebin.com', port=443, path='/', scheme="http"):
    url = security.strip_dangerous_characters(f"{scheme}://{host}:{port}{path}")
    cmd = helpers.run_cmd(f'curl --insecure {url}')
"""

_REQ_SRC = r"(?:req\.|request\.)"
_U = r"(?:req\.|request\.)"

regex = re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|subprocess\.(?:run|call|check_output|Popen))\s*\([^)]*"
        + _U + r"|shell\s*=\s*True")

print("Regex 1:", regex.search(text))

text2 = """
def run_cmd(cmd):
  return os.popen(cmd).read()
"""

print("Regex 2:", regex.search(text2))
