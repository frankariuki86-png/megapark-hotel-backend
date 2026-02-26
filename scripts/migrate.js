const fs = require('fs');
const path = require('path');
require('dotenv').config();
const { Client } = require('pg');

const migrationsDir = path.join(__dirname, '..', 'migrations');
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('DATABASE_URL not set. Set it in environment or .env');
  process.exit(2);
}

const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();

(async () => {
  const client = new Client({ connectionString: DATABASE_URL, ssl: (process.env.PGSSLMODE === 'require') ? { rejectUnauthorized: false } : false });
  try {
    await client.connect();
    console.log('Connected to Postgres, running migrations...');
    for (const file of files) {
      const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      console.log('Running', file);
      await client.query(sql);
    }
    console.log('Migrations applied successfully');
    await client.end();
    process.exit(0);
  } catch (err) {
    console.error('Migration failed:', err.message || err);
    process.exit(1);
  }
})();
const { Client } = require('pg');
require('dotenv').config();

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL not set. Cannot run migrations.');
  process.exit(1);
}

const fs = require('fs');
const path = require('path');

const runMigrations = async () => {
  const client = new Client({ connectionString: DATABASE_URL });
  try {
    await client.connect();
    console.log('✓ Connected to database');

    const migrationsDir = path.join(__dirname, '..', 'migrations');
    const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();

    for (const file of files) {
      const filePath = path.join(migrationsDir, file);
      const sql = fs.readFileSync(filePath, 'utf8');
      console.log(`\nRunning migration: ${file}`);
      try {
        await client.query(sql);
        console.log(`✓ ${file} completed`);
      } catch (e) {
        console.error(`✗ ${file} failed:`, e.message);
        throw e;
      }
    }

    console.log('\n✓ All migrations completed');
  } catch (e) {
    console.error('Migration error:', e.message);
    process.exit(1);
  } finally {
    await client.end();
  }
};

runMigrations();
