import re
with open('tests/test_hooks.py', 'r') as f:
    text = f.read()

# When testing git hooks in a temporary repository, explicitly set core.hooksPath to .git/hooks locally to prevent global git configurations (like /dev/null) from bypassing the hook execution in the test environment.
import subprocess
text = text.replace('subprocess.run(["git", "add", "-A"], cwd=self.root, check=True, env=env)', 'subprocess.run(["git", "config", "core.hooksPath", ".git/hooks"], cwd=self.root, check=True, env=env)\n        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True, env=env)')

with open('tests/test_hooks.py', 'w') as f:
    f.write(text)
