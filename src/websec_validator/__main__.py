"""`python -m websec_validator …` — the same CLI as the `websec` console script.

For environments where the console script is not on PATH (a user-site or pyenv install that was not
rehashed, a CI image, an agent VM): the interpreter that installed the package can always run it.
"""

import sys

from .cli import main

sys.exit(main())
