import unittest
from websec_validator.extractors.surface import SurfaceExtractor
from websec_validator.extractors.base import RepoContext

def repo(files: dict) -> RepoContext:
    class DummyRepoContext(RepoContext):
        def __init__(self, f):
            self.f = f
        def iter_code(self):
            for path, content in self.f.items():
                yield type('Path', (), {'suffix': '.' + path.split('.')[-1]})(), path, content
    return DummyRepoContext(files)

class PrototypePollutionRegressionTests(unittest.TestCase):
    def test_prototype_pollution_misses_fn_hunt(self):
        ctx = repo({
            "test_wrapper.js": """
                const express = require('express');
                const _ = require('lodash');
                const app = express();
                function mergePayload(payload) {
                    let obj = {};
                    _.merge(obj, payload); // Sink
                    return obj;
                }
                app.post('/miss1', (req, res) => {
                    mergePayload(req.body);
                });
            """,
            "test_destructuring.js": """
                app.post('/miss2', (req, res) => {
                    let obj = {};
                    const { updates } = req.body;
                    _.merge(obj, updates); // Sink
                });
            """,
            "test_koa_ctx.js": """
                app.post('/miss3', (ctx, res) => {
                    let obj = {};
                    _.defaultsDeep(obj, ctx.request.body); // Sink
                });
            """,
            "test_fastify_req.js": """
                app.post('/miss4', (request, reply) => {
                    let obj = {};
                    Object.assign(obj, request.body); // Sink
                });
            """,
            "test_hono_c.js": """
                app.post('/miss5', (c, res) => {
                    let obj = {};
                    Object.assign(obj, c.req.json()); // Sink
                });
            """,
            "test_safe_constant.js": """
                app.post('/safe1', (req, res) => {
                    let obj = {};
                    _.merge(obj, { allowed: "constant" }); // Safe
                });
            """,
            "test_safe_literal.js": """
                app.post('/safe2', (req, res) => {
                    let obj = {};
                    _.merge(obj, "string literal"); // Safe
                });
            """
        })

        results = SurfaceExtractor().extract(ctx, facts={"stack": {"languages": ["javascript"]}, "routes": {"endpoints": [{}]}})
        sinks = results.get('sinks', {})

        pp = sinks.get("prototype-pollution", {}).get("files", [])

        # We expect the misses to be flagged now.
        self.assertIn("test_wrapper.js", pp)
        self.assertIn("test_destructuring.js", pp)
        self.assertIn("test_koa_ctx.js", pp)
        self.assertIn("test_fastify_req.js", pp)
        self.assertIn("test_hono_c.js", pp)

        # And we expect safe cases to be ignored.
        self.assertNotIn("test_safe_constant.js", pp)
        self.assertNotIn("test_safe_literal.js", pp)

if __name__ == '__main__':
    unittest.main()
