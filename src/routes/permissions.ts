import { Router, Request, Response } from 'express';
import pool from '../config/db';
import { requireAuth } from '../middleware/auth';
import { registrarAuditoria } from '../utils/audit';
import { broadcastToWeb } from '../websocket/server';

const router = Router();

router.use(requireAuth);

// GET /api/v1/permissions?usuario_id=...&dispositivo_id=...
router.get('/', async (req: Request, res: Response) => {
  const { usuario_id, dispositivo_id } = req.query;
  const condiciones: string[] = [];
  const params: any[] = [];

  if (usuario_id) { params.push(usuario_id); condiciones.push(`p.usuario_id = $${params.length}`); }
  if (dispositivo_id) { params.push(dispositivo_id); condiciones.push(`p.dispositivo_id = $${params.length}`); }

  const where = condiciones.length ? `WHERE ${condiciones.join(' AND ')}` : '';

  try {
    const result = await pool.query(
      `SELECT p.*, u.nombre, u.apellido, d.ubicacion
       FROM permisos p
       JOIN usuarios u ON u.id = p.usuario_id
       JOIN dispositivos_cerradura d ON d.id = p.dispositivo_id
       ${where}
       ORDER BY d.ubicacion, u.apellido`,
      params
    );
    res.json(result.rows);
  } catch (err) {
    console.error('[PERMISSIONS] Error al listar:', err);
    res.status(500).json({ error: 'Error al listar permisos' });
  }
});

// POST /api/v1/permissions
router.post('/', async (req: Request, res: Response) => {
  const { usuario_id, dispositivo_id, hora_inicio, hora_fin, dias_semana, fecha_limite } = req.body;

  if (!usuario_id || !dispositivo_id || !fecha_limite) {
    res.status(400).json({ error: 'usuario_id, dispositivo_id y fecha_limite son obligatorios' });
    return;
  }

  try {
    const result = await pool.query(
      `INSERT INTO permisos (usuario_id, dispositivo_id, hora_inicio, hora_fin, dias_semana, fecha_limite)
       VALUES ($1, $2, COALESCE($3::time, '00:00:00'::time), COALESCE($4::time, '23:59:59'::time), COALESCE($5::int[], '{1,2,3,4,5,6,7}'::int[]), $6::timestamp)
       RETURNING *`,
      [usuario_id, dispositivo_id, hora_inicio || null, hora_fin || null, dias_semana || null, fecha_limite]
    );

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'CREAR_PERMISO',
        payload: { usuario_id, dispositivo_id, hora_inicio, hora_fin, dias_semana, fecha_limite },
        ip: req.ip,
      });
    }

    broadcastToWeb('sync_credentials', { accion: 'CREAR_PERMISO', permiso_id: result.rows[0].id });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('[PERMISSIONS] Error al crear:', err);
    res.status(500).json({ error: 'Error al crear el permiso' });
  }
});

// PUT /api/v1/permissions/:id
router.put('/:id', async (req: Request, res: Response) => {
  const { hora_inicio, hora_fin, dias_semana, fecha_limite, activo } = req.body;
  try {
    const result = await pool.query(
      `UPDATE permisos SET
         hora_inicio = COALESCE($1::time, hora_inicio),
         hora_fin = COALESCE($2::time, hora_fin),
         dias_semana = COALESCE($3::int[], dias_semana),
         fecha_limite = COALESCE($4::timestamp, fecha_limite),
         activo = COALESCE($5::boolean, activo)
       WHERE id = $6
       RETURNING *`,
      [hora_inicio || null, hora_fin || null, dias_semana || null, fecha_limite || null, activo ?? null, req.params.id]
    );
    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Permiso no encontrado' });
      return;
    }

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'EDITAR_PERMISO',
        payload: { permiso_id: req.params.id, cambios: req.body },
        ip: req.ip,
      });
    }

    broadcastToWeb('sync_credentials', { accion: 'EDITAR_PERMISO', permiso_id: req.params.id });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error al editar el permiso' });
  }
});

// PATCH /api/v1/permissions/:id/pause
router.patch('/:id/pause', async (req: Request, res: Response) => {
  try {
    const result = await pool.query(
      `UPDATE permisos SET activo = FALSE WHERE id = $1 RETURNING id`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Permiso no encontrado' });
      return;
    }

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'PAUSAR_PERMISO',
        payload: { permiso_id: req.params.id },
        ip: req.ip,
      });
    }

    broadcastToWeb('sync_credentials', { accion: 'PAUSAR_PERMISO', permiso_id: req.params.id });
    res.json({ ok: true, mensaje: 'Permiso pausado' });
  } catch (err) {
    res.status(500).json({ error: 'Error al pausar el permiso' });
  }
});

// DELETE /api/v1/permissions/:id
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const result = await pool.query(`DELETE FROM permisos WHERE id = $1 RETURNING id`, [req.params.id]);
    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Permiso no encontrado' });
      return;
    }

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'ELIMINAR_PERMISO',
        payload: { permiso_id: req.params.id },
        ip: req.ip,
      });
    }

    broadcastToWeb('sync_credentials', { accion: 'ELIMINAR_PERMISO', permiso_id: req.params.id });
    res.json({ ok: true, mensaje: 'Permiso eliminado' });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar el permiso' });
  }
});

export default router;
