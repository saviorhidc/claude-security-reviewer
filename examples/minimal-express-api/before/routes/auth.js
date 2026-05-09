const express = require('express');
const db = require('../db');

const router = express.Router();

// VULNERABILITY: High WeakRateLimiting — no rate limiting on the login endpoint
// An attacker can brute-force credentials without any throttle. express-rate-limit or a Redis-backed
// limiter is required here.
router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    const result = await db.query(
      'SELECT id, username, password FROM users WHERE username = $1',
      [username]
    );

    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // VULNERABILITY: Critical SecretsExposure — plaintext password comparison; passwords stored and compared in cleartext
    // Passwords must be hashed at rest (argon2id/bcrypt). Storing and comparing plaintext means
    // a database read is a full credential compromise.
    if (user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const sessionToken = Math.random().toString(36).slice(2);

    // VULNERABILITY: High InsecureCookie — session cookie set without httpOnly, secure, or sameSite flags
    // JS code can read this cookie (no httpOnly), it travels over HTTP (no secure), and CSRF is not
    // mitigated (no sameSite).
    res.cookie('session', sessionToken, {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.post('/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

module.exports = router;
