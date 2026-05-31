const express = require('express');
const router = express.Router();

router.use(requireAuth);

router.get('/api/users/:id', (req, res) => {
  const id = req.params.id;
  res.json({ id });
});

router.post('/api/groups/:groupId/items', (req, res) => {
  // outbound fetch on user-controlled url → SSRF sink
  fetch(req.body.url).then((r) => r.json());
});

module.exports = router;
