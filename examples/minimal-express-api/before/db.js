// VULNERABILITY: Critical SecretsExposure — hardcoded DB password committed to source
// The password belongs in an env var (process.env.DB_PASSWORD), not here.
const { Pool } = require('pg');

const db = new Pool({
  host: 'localhost',
  port: 5432,
  database: 'appdb',
  user: 'appuser',
  password: 'changeme', // VULNERABILITY: Critical SecretsExposure — plaintext credential in source file
});

module.exports = db;
