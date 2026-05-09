// VULNERABILITY: Medium MissingSecurityHeaders — no security headers middleware (no helmet, no CSP, no HSTS)
const express = require('express');
const cors = require('cors');

const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const ordersRoutes = require('./routes/orders');

const app = express();

// VULNERABILITY: High CORSMisconfiguration — wildcard origin combined with credentials:true
// Browsers block this combination, but the intent is wrong and some non-browser clients honour credentials anyway.
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));

// VULNERABILITY: Medium InputValidation — 50 MB body limit is far too large for a JSON API; DoS via oversized payload
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

app.use('/auth', authRoutes);
app.use('/admin', adminRoutes);
app.use('/orders', ordersRoutes);

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// VULNERABILITY: Medium ErrorLeakage — raw err.message and err.stack returned to the client
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    code: err.code,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});

module.exports = app;
