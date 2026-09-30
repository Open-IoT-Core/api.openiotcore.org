import dotenv from 'dotenv';
dotenv.config();

import bcrypt from 'bcryptjs';
import pool from '../src/config/db';

async function main() {
  const [correo, clave, nombre, apellido] = process.argv.slice(2);

  if (!correo || !clave || !nombre || !apellido) {
    console.error('Uso: bun run scripts/create-admin.ts <correo> <clave> <nombre> <apellido>');
    process.exit(1);
  }

  const passwordHash = await bcrypt.hash(clave, 10);

  try {
    const result = await pool.query(
      `INSERT INTO usuarios (nombre, apellido, correo, departamento, rol, password_hash)
       VALUES ($1, $2, $3, 'Administración', 'ADMIN', $4)
       ON CONFLICT (correo) DO UPDATE SET password_hash = EXCLUDED.password_hash, rol = 'ADMIN'
       RETURNING id, correo, rol`,
      [nombre, apellido, correo, passwordHash]
    );

    console.log('Administrador listo:', result.rows[0]);
  } catch (err) {
    console.error('Error al crear el administrador:', err);
  } finally {
    await pool.end();
  }
}

main();
