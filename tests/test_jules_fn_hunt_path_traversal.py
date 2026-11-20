import unittest
from websec_validator.extractors.surface import SurfaceExtractor
from websec_validator.extractors.base import RepoContext

def repo(files: dict) -> RepoContext:
    from tests.test_pentest_regressions import repo as original_repo
    return original_repo(files)

class JulesFnHuntPathTraversalTests(unittest.TestCase):
    def test_sync_methods_detect(self):
        ctx = repo({
            "test.js": """
const fs = require('fs');
const express = require('express');
const app = express();

app.get('/sync-methods', (req, res) => {
    let data = fs.readFileSync(req.query.file);
    fs.writeFileSync(req.query.out, data);
    fs.unlinkSync(req.query.old);
    let files = fs.readdirSync(req.query.dir);
    fs.rmdirSync(req.query.rm);
    fs.rmSync(req.query.rm2);
    res.send("ok");
});
"""
        })
        ex = SurfaceExtractor()
        res = ex.extract(ctx, facts={})
        findings = res.get("sink_occurrences", [])
        pt = [f for f in findings if f.get("attack_class") == "path-traversal"]
        self.assertEqual(len(pt), 6, f"Expected 6 path traversal findings for Sync methods, got {len(pt)}")
        sinks = {f["sink"] for f in pt}
        self.assertEqual(sinks, {"fs.readFileSync", "fs.writeFileSync", "fs.unlinkSync", "fs.readdirSync", "fs.rmdirSync", "fs.rmSync"})

    def test_sync_methods_safe(self):
        ctx = repo({
            "test.js": """
const fs = require('fs');
const express = require('express');
const app = express();

app.get('/sync-methods-safe', (req, res) => {
    let file = "config.json";
    let data = fs.readFileSync(file);
    fs.writeFileSync("out.txt", data);
    fs.unlinkSync("temp.txt");
    let files = fs.readdirSync("./dir");
    fs.rmdirSync("./dir2");
    fs.rmSync("./dir3");
    res.send("ok");
});
"""
        })
        ex = SurfaceExtractor()
        res = ex.extract(ctx, facts={})
        findings = res.get("sink_occurrences", [])
        pt = [f for f in findings if f.get("attack_class") == "path-traversal"]
        self.assertEqual(len(pt), 0, "Expected 0 path traversal findings for safe Sync methods")

    def test_async_methods_detect(self):
        ctx = repo({
            "test.js": """
const fs = require('fs');
const express = require('express');
const app = express();

app.get('/async-methods', (req, res) => {
    fs.rmdir(req.query.rm, () => {});
    fs.rm(req.query.rm2, () => {});
    res.send("ok");
});
"""
        })
        ex = SurfaceExtractor()
        res = ex.extract(ctx, facts={})
        findings = res.get("sink_occurrences", [])
        pt = [f for f in findings if f.get("attack_class") == "path-traversal"]
        self.assertEqual(len(pt), 2, f"Expected 2 path traversal findings for async rm/rmdir methods, got {len(pt)}")
        sinks = {f["sink"] for f in pt}
        self.assertEqual(sinks, {"fs.rmdir", "fs.rm"})

    def test_async_methods_safe(self):
        ctx = repo({
            "test.js": """
const fs = require('fs');
const express = require('express');
const app = express();

app.get('/async-methods-safe', (req, res) => {
    fs.rmdir("./dir2", () => {});
    fs.rm("./dir3", () => {});
    res.send("ok");
});
"""
        })
        ex = SurfaceExtractor()
        res = ex.extract(ctx, facts={})
        findings = res.get("sink_occurrences", [])
        pt = [f for f in findings if f.get("attack_class") == "path-traversal"]
        self.assertEqual(len(pt), 0, "Expected 0 path traversal findings for safe async methods")
