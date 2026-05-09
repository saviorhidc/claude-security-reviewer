const express = require('express');
const db = require('../db');

const router = express.Router();

// GET /orders/:id
//
// VULNERABILITY: Critical SQLInjection — req.params.id is interpolated directly into a template literal SQL string.
// An attacker passes a value like:  1 OR 1=1  or  1; DROP TABLE orders; --
// to execute arbitrary SQL. Use parameterized queries: db.query('SELECT ... WHERE id = $1', [req.params.id])
//
// VULNERABILITY: Critical BrokenAuthorization (IDOR) — the query fetches any order by its numeric id with
// no ownership constraint. A logged-in user can read any other user's order by guessing sequential IDs.
// Fix: add AND user_id = $2 with the authenticated user's id from the session.
router.get('/:id', async (req, res, next) => {
  try {
    const { id } = req.params;

    // VULNERABILITY: Critical SQLInjection
    const result = await db.query(
      `SELECT * FROM orders WHERE id = ${id}`
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: 'Not found' });
    }

    // VULNERABILITY: Critical BrokenAuthorization — returned without verifying result.rows[0].user_id
    // matches the authenticated user
    res.json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
