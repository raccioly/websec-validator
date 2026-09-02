import re
_U = r"(?:req\.|request\.|\+|`[^`]*\$\{|f['\"]|%\s*[\(%]|\.format\s*\(|searchParams|nextUrl|params\[)"

text = """
    cmd = helpers.run_cmd(f'curl --insecure {url}')
"""

# Let's see if there's any other way `run_cmd` is picked up. Right now, `run_cmd` isn't a sink at all.
# If we add `os.popen`, `core/helpers.py` will flag `os.popen(cmd)` as a command-injection sink.
# But `core/helpers.py` is not a web handler, so it won't be flagged if `no_web_surface` is true. But `app.py` has web handlers, so `no_web_surface` is false for the repo.
# Is `core/helpers.py` considered a `nonserver`?
