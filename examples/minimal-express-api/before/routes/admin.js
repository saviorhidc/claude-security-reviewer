const express = require('express');
const db = require('../db');

const router = express.Router();

// VULNERABILITY: Critical MissingAuthentication — no auth check before returning user data
// There is no middleware or inline check verifying the caller holds a valid session.
// Any unauthenticated request to GET /admin/users returns the full user table.
router.get('/users', async (req, res, next) => {
  try {
    const result = await db.query('SELECT * FROM users');
    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
