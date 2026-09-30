import { Pool } from 'pg';

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 5432,
  max: 10,
  idleTimeoutMillis: 30000,
});

pool.on('error', (err: Error) => {
  console.error('[DB] Error inesperado en el pool de conexiones:', err);
});

export default pool;
