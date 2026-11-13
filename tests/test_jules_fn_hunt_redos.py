import unittest
import tempfile
from pathlib import Path
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.surface import SurfaceExtractor

def repo(files: dict) -> RepoContext:
    d = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return RepoContext(d)

class FalsePositiveRegressionTests(unittest.TestCase):
    def test_redos_fstring_and_template_literal(self):
        ctx = repo({
            "vuln.js": """
                const express = require('express');
                const app = express();
                app.get('/test', (req, res) => {
                    let regex = req.query.regex;
                    let r = new RegExp(`^${regex}$`); // vulnerable: template string
                });
            """,
            "vuln.py": """
                import re
                from flask import request
                def run():
                    regex = request.args.get('regex')
                    re.search(f"{regex}", "string") # vulnerable: f-string
            """,
            "safe.js": """
                const express = require('express');
                const app = express();
                app.get('/test', (req, res) => {
                    let r = new RegExp(`^[a-z]*$`); // safe: constant without +
                    let regex = req.query.regex;
                    console.log(regex);
                });
            """,
            "safe.py": """
                import re
                from flask import request
                def run():
                    re.search(f"^[a-z]*$", "string") # safe: constant without +
                    regex = request.args.get('regex')
                    print(regex)
            """,
            "safe2.py": """
                import re
                def safe_compile(cmd):
                    re.compile(cmd)
            """
        })
        # Add frameworks so no_web_surface doesn't block evaluation
        facts = {"routes": {"endpoints": [{"method": "GET", "path": "/test"}]}, "stack": {"frameworks": ["express", "flask"], "languages": ["node", "python"]}}
        result = SurfaceExtractor().extract(ctx, facts)
        occurrences = result.get("sink_occurrences", [])

        redos = [row for row in occurrences if row["sink_class"] == "redos"]

        # Should have found 2 vulnerable redos instances (one from JS, one from Python)
        self.assertEqual(len(redos), 2)

        # Verify the matches are exactly the vulnerable ones
        vuln_files = {row["file"] for row in redos}
        self.assertIn("vuln.js", vuln_files)
        self.assertIn("vuln.py", vuln_files)

        # Safe files must NOT have any redos findings
        self.assertNotIn("safe.js", vuln_files)
        self.assertNotIn("safe.py", vuln_files)
        self.assertNotIn("safe2.py", vuln_files)

if __name__ == '__main__':
    unittest.main()
