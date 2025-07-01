// db.js
require('dotenv').config(); // Load environment variables from .env file
const { Pool } = require('pg'); // Import the Pool class from the pg module

// Create a new Pool instance using environment variables
// This pool will manage connections to your PostgreSQL database
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT, // Ensure this matches your PostgreSQL instance (e.g., 5434)
});

// Optional: Add an event listener to confirm successful connection when a client is acquired
pool.on('connect', () => {
  console.log('Pool: Connected to the PostgreSQL database!');
});

// Optional: Add an event listener for any errors on idle clients in the pool
pool.on('error', (err, client) => {
  console.error('Pool: Unexpected error on idle client', err);
  // It's good practice to log the error, but crashing the process here might be too aggressive
  // process.exit(-1); // Only uncomment this if you want the app to crash on unexpected DB errors
});

// Export the pool so it can be used in other files (like server.js)
module.exports = pool;