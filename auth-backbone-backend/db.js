import dotenv from "dotenv";
dotenv.config();

import pg from "pg";

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.SUPABASE_DB_URL,
  ssl: false // Change this line
});

// Test connection
async function testConnection() {
  try {
    const client = await pool.connect();
    console.log('✅ Database connection established successfully!');
    
    const result = await client.query('SELECT NOW() as current_time');
    console.log('✅ Test query executed:', result.rows[0].current_time);
    
    client.release();
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
  }
}

testConnection();

// Listen for connection events
pool.on('connect', () => {
  console.log('✅ New client connected to database');
});

pool.on('error', (err) => {
  console.error('❌ Database connection error:', err);
});