import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import pool from '../config/db';
import { requireAuth, requireRole } from '../middleware/auth';
import { registrarAuditoria } from '../utils/audit';
import { UserRow } from '../types';

const router = Router();

router.use(requireAuth);

// GET /api/v1/users?estado=ACTIVO
router.get('/', async (req: Request, res: Response) => {
  const { estado } = req.query;
  try {
    const params: any[] = [];
    let where = '';
    if (estado) {
      params.push(estado);
      where = 'WHERE estado = $1';
    }
    const result = await pool.query<UserRow>(
      `SELECT id, nombre, apellido, correo, departamento, estado, rol, creado_en
       FROM usuarios ${where} ORDER BY creado_en DESC`,
      params
    );
    res.json(result.rows);
  } catch (err) {
    console.error('[USERS] Error al listar:', err);
    res.status(500).json({ error: 'Error al listar usuarios' });
  }
});

// GET /api/v1/users/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const result = await pool.query<UserRow>(
      `SELECT id, nombre, apellido, correo, departamento, estado, rol, creado_en
       FROM usuarios WHERE id = $1`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Usuario no encontrado' });
      return;
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener usuario' });
  }
});

// POST /api/v1/users (solo ADMIN)
router.post('/', requireRole('ADMIN'), async (req: Request, res: Response) => {
  const { nombre, apellido, correo, departamento, rol, clave } = req.body;

  if (!nombre || !apellido || !correo || !departamento) {
    res.status(400).json({ error: 'nombre, apellido, correo y departamento son obligatorios' });
    return;
  }

  try {
    const passwordHash = clave ? await bcrypt.hash(clave, 10) : null;
    const result = await pool.query<UserRow>(
      `INSERT INTO usuarios (nombre, apellido, correo, departamento, rol, password_hash)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, nombre, apellido, correo, departamento, estado, rol, creado_en`,
      [nombre, apellido, correo, departamento, rol || 'USUARIO', passwordHash]
    );

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'CREAR_USUARIO',
        payload: { usuario_creado: result.rows[0].id, correo },
        ip: req.ip,
      });
    }

    res.status(201).json(result.rows[0]);
  } catch (err: any) {
    if (err.code === '23505') {
      res.status(409).json({ error: 'Ya existe un usuario con ese correo' });
      return;
    }
    console.error('[USERS] Error al crear:', err);
    res.status(500).json({ error: 'Error al crear usuario' });
  }
});

// PUT /api/v1/users/:id (ADMIN o propio usuario)
router.put('/:id', async (req: Request, res: Response) => {
  const usuarioActual = req.usuario;
  if (!usuarioActual) {
    res.status(401).json({ error: 'No autenticado' });
    return;
  }

  const esPropio = usuarioActual.id === req.params.id;
  if (usuarioActual.rol !== 'ADMIN' && !esPropio) {
    res.status(403).json({ error: 'No tienes permisos para editar este usuario' });
    return;
  }

  const { nombre, apellido, departamento, estado, rol, clave } = req.body;

  try {
    const passwordHash = clave ? await bcrypt.hash(clave, 10) : null;

    const result = await pool.query<UserRow>(
      `UPDATE usuarios SET
         nombre = COALESCE($1, nombre),
         apellido = COALESCE($2, apellido),
         departamento = COALESCE($3, departamento),
         estado = COALESCE($4, estado),
         rol = CASE WHEN $6 = 'ADMIN' THEN COALESCE($5, rol) ELSE rol END,
         password_hash = COALESCE($7, password_hash)
       WHERE id = $8
       RETURNING id, nombre, apellido, correo, departamento, estado, rol, creado_en`,
      [nombre, apellido, departamento, estado, rol, usuarioActual.rol, passwordHash, req.params.id]
    );

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Usuario no encontrado' });
      return;
    }

    await registrarAuditoria({
      adminId: usuarioActual.id,
      accion: 'EDITAR_USUARIO',
      payload: { usuario_editado: req.params.id, cambios: req.body },
      ip: req.ip,
    });

    res.json(result.rows[0]);
  } catch (err) {
    console.error('[USERS] Error al editar:', err);
    res.status(500).json({ error: 'Error al editar usuario' });
  }
});

// DELETE /api/v1/users/:id (solo ADMIN)
router.delete('/:id', requireRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const result = await pool.query(
      `UPDATE usuarios SET estado = 'INACTIVO' WHERE id = $1 RETURNING id`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Usuario no encontrado' });
      return;
    }

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'DESACTIVAR_USUARIO',
        payload: { usuario_desactivado: req.params.id },
        ip: req.ip,
      });
    }

    res.json({ ok: true, mensaje: 'Usuario desactivado' });
  } catch (err) {
    res.status(500).json({ error: 'Error al desactivar usuario' });
  }
});

export default router;
