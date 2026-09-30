import { Router, Request, Response } from 'express';
import pool from '../config/db';
import { requireAuth } from '../middleware/auth';
import { registrarAuditoria } from '../utils/audit';

const router = Router();

router.use(requireAuth);

// GET /api/v1/credentials?usuario_id=...
router.get('/', async (req: Request, res: Response) => {
  const { usuario_id } = req.query;
  try {
    const params: any[] = [];
    let where = '';
    if (usuario_id) {
      params.push(usuario_id);
      where = 'WHERE c.usuario_id = $1';
    }
    const result = await pool.query(
      `SELECT c.id, c.uid_hex, c.tipo, c.estado, c.emitida_en, c.expira_en,
              u.id AS usuario_id, u.nombre, u.apellido, u.correo
       FROM credenciales c
       JOIN usuarios u ON u.id = c.usuario_id
       ${where}
       ORDER BY c.emitida_en DESC`,
      params
    );
    res.json(result.rows);
  } catch (err) {
    console.error('[CREDENTIALS] Error al listar:', err);
    res.status(500).json({ error: 'Error al listar credenciales' });
  }
});

// POST /api/v1/credentials
router.post('/', async (req: Request, res: Response) => {
  const { uid_hex, usuario_id, expira_en, tipo } = req.body;

  if (!uid_hex || !usuario_id || !expira_en) {
    res.status(400).json({ error: 'uid_hex, usuario_id y expira_en son obligatorios' });
    return;
  }

  try {
    const result = await pool.query(
      `INSERT INTO credenciales (uid_hex, usuario_id, expira_en, tipo)
       VALUES ($1, $2, $3, COALESCE($4, 'RFID_13.56MHZ'))
       RETURNING id, uid_hex, tipo, estado, usuario_id, emitida_en, expira_en`,
      [uid_hex.toUpperCase(), usuario_id, expira_en, tipo]
    );

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'VINCULAR_CREDENCIAL',
        payload: { uid_hex: uid_hex.toUpperCase(), usuario_id },
        ip: req.ip,
      });
    }

    res.status(201).json(result.rows[0]);
  } catch (err: any) {
    if (err.code === '23505') {
      res.status(409).json({ error: 'Esa tarjeta (UID) ya está registrada' });
      return;
    }
    console.error('[CREDENTIALS] Error al crear:', err);
    res.status(500).json({ error: 'Error al vincular credencial' });
  }
});

// PATCH /api/v1/credentials/:id/revoke
router.patch('/:id/revoke', async (req: Request, res: Response) => {
  try {
    const result = await pool.query(
      `UPDATE credenciales SET estado = 'REVOCADA' WHERE id = $1 RETURNING id, uid_hex`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Credencial no encontrada' });
      return;
    }

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'REVOCAR_CREDENCIAL',
        payload: { credencial_id: req.params.id, uid_hex: result.rows[0].uid_hex },
        ip: req.ip,
      });
    }

    res.json({ ok: true, mensaje: 'Credencial revocada' });
  } catch (err) {
    res.status(500).json({ error: 'Error al revocar credencial' });
  }
});

// PATCH /api/v1/credentials/:id/reactivate
router.patch('/:id/reactivate', async (req: Request, res: Response) => {
  try {
    const result = await pool.query(
      `UPDATE credenciales SET estado = 'ACTIVA' WHERE id = $1 RETURNING id`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Credencial no encontrada' });
      return;
    }

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'REACTIVAR_CREDENCIAL',
        payload: { credencial_id: req.params.id },
        ip: req.ip,
      });
    }

    res.json({ ok: true, mensaje: 'Credencial reactivada' });
  } catch (err) {
    res.status(500).json({ error: 'Error al reactivar credencial' });
  }
});

// DELETE /api/v1/credentials/:id
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const result = await pool.query(`DELETE FROM credenciales WHERE id = $1 RETURNING uid_hex`, [req.params.id]);
    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Credencial no encontrada' });
      return;
    }

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'ELIMINAR_CREDENCIAL',
        payload: { uid_hex: result.rows[0].uid_hex },
        ip: req.ip,
      });
    }

    res.json({ ok: true, mensaje: 'Credencial eliminada' });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar credencial' });
  }
});

export default router;
