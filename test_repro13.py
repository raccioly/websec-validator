import re

text2 = """
def run_cmd(cmd):
  return os.popen(cmd).read()
"""

# Let's see if we just match `os.popen(cmd)` without requiring `req.` or `request.`
# Wait, `cmd` is untrusted here? Not necessarily from `req.`, but it's a function parameter.
from websec_validator.extractors.surface import SINKS
print("Regex text2:", SINKS["command-injection"][2].search(text2))
