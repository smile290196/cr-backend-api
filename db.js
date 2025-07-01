const { Pool } = require('pg');

// Check if we are in a production environment
const isProduction = process.env.NODE_ENV === 'production';

// The connection string for the database
// In production (on Render), process.env.DATABASE_URL will be provided.
// Locally, it can fallback to a local connection string or separate env variables.
// For simplicity, for local development you can still use a .env file or hardcode for dev.
// Here, we assume DATABASE_URL will be provided by Render, and if not,
// you might have PGUSER, PGPASSWORD etc. in your local .env or hardcoded.
// For this guide, let's ensure it uses DATABASE_URL in production.
const connectionString = process.env.DATABASE_URL;

const pool = new Pool({
  connectionString: connectionString,
  // Render requires SSL for external connections
  ssl: isProduction ? { rejectUnauthorized: false } : false,
});

module.exports = pool;