const { Client } = require('pg');
require('dotenv').config();

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error('ERROR: DATABASE_URL is not set in environment or .env');
  process.exit(2);
}

const client = new Client({ connectionString, connectionTimeoutMillis: 5000 });

(async () => {
  try {
    await client.connect();
    const res = await client.query('SELECT NOW() AS now');
    console.log('Postgres connection OK. server_time=', res.rows[0].now);
    await client.end();
    process.exit(0);
  } catch (err) {
    console.error('Postgres connection FAILED:', err.message || err);
    process.exit(1);
  }
})();
