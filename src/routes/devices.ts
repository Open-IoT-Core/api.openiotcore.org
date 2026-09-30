import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import pool from '../config/db';
import { requireAuth, requireRole } from '../middleware/auth';
import { registrarAuditoria } from '../utils/audit';
import { sendToDevice, broadcastToWeb, isDeviceConnected } from '../websocket/server';

const router = Router();

router.use(requireAuth);

const SQL_ESTADO_EFECTIVO = `
  CASE
    WHEN ultimo_heartbeat IS NOT NULL AND ultimo_heartbeat > NOW() - INTERVAL '2 minutes'
      THEN 'ONLINE'
    ELSE 'OFFLINE'
  END AS estado_efectivo
`;

/**
 * GET /api/v1/devices/my-devices
 * Devuelve todas las cerraduras asociadas al usuario autenticado (ya sea propietario o con permiso).
 */
router.get('/my-devices', async (req: Request, res: Response) => {
  const userId = req.usuario?.id;
  try {
    const result = await pool.query(
      `SELECT DISTINCT d.id, d.ubicacion, d.zona_piso, d.direccion_ip, d.mac_address,
               d.estado_conexion, d.ultimo_heartbeat, d.propietario_id, ${SQL_ESTADO_EFECTIVO}
       FROM dispositivos_cerradura d
       LEFT JOIN permisos p ON p.dispositivo_id = d.id AND p.usuario_id = $1 AND p.activo = TRUE
       WHERE d.propietario_id = $1 OR p.id IS NOT NULL
       ORDER BY d.ubicacion`,
      [userId]
    );

    const devices = result.rows.map((dev) => ({
      ...dev,
      websocket_active: isDeviceConnected(dev.id),
      es_propietario: dev.propietario_id === userId,
    }));

    res.json(devices);
  } catch (err) {
    console.error('[DEVICES] Error obteniendo mis dispositivos:', err);
    res.status(500).json({ error: 'Error al obtener tus dispositivos' });
  }
});

/**
 * POST /api/v1/devices/register
 * Permite a cualquier usuario registrado añadir/vincular manualmente una cerradura a su cuenta.
 * Body: { id, ubicacion, zona_piso, direccion_ip, mac_address, clave_secreta? }
 */
router.post('/register', async (req: Request, res: Response) => {
  const { id, ubicacion, zona_piso, direccion_ip, mac_address, clave_secreta } = req.body;
  const userId = req.usuario?.id;

  if (!id || !ubicacion || !zona_piso || !direccion_ip || !mac_address) {
    res.status(400).json({ error: 'id, ubicacion, zona_piso, direccion_ip y mac_address son obligatorios' });
    return;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const claveSecretaFinal = clave_secreta || crypto.randomBytes(24).toString('hex');
    const claveHash = await bcrypt.hash(claveSecretaFinal, 10);

    const devResult = await client.query(
      `INSERT INTO dispositivos_cerradura
         (id, ubicacion, zona_piso, direccion_ip, mac_address, clave_secreta_hash, propietario_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, ubicacion, zona_piso, direccion_ip, mac_address, estado_conexion, propietario_id`,
      [id, ubicacion, zona_piso, direccion_ip, mac_address, claveHash, userId]
    );

    // Crear permiso automático 24/7 para el propietario
    const fechaLimite = new Date();
    fechaLimite.setFullYear(fechaLimite.getFullYear() + 10);

    await client.query(
      `INSERT INTO permisos (usuario_id, dispositivo_id, hora_inicio, hora_fin, dias_semana, fecha_limite, activo)
       VALUES ($1, $2, '00:00:00', '23:59:59', '{1,2,3,4,5,6,7}', $3, TRUE)`,
      [userId, id, fechaLimite]
    );

    await client.query('COMMIT');

    if (userId) {
      await registrarAuditoria({
        adminId: userId,
        accion: 'REGISTRAR_DISPOSITIVO_PROPIO',
        payload: { dispositivo_id: id, ubicacion },
        ip: req.ip,
      });
    }

    broadcastToWeb('device_registered', { deviceId: id, propietario_id: userId });

    res.status(201).json({
      mensaje: 'Cerradura vinculada con éxito a tu cuenta',
      dispositivo: devResult.rows[0],
      clave_secreta: claveSecretaFinal,
      aviso: 'Configura esta clave secreta en el firmware de la cerradura.',
    });
  } catch (err: any) {
    await client.query('ROLLBACK');
    if (err.code === '23505') {
      res.status(409).json({ error: 'Ya existe un dispositivo registrado con este id o dirección MAC' });
      return;
    }
    console.error('[DEVICES] Error en registro de usuario:', err);
    res.status(500).json({ error: 'Error al vincular el dispositivo' });
  } finally {
    client.release();
  }
});

/**
 * POST /api/v1/devices/:id/verify
 * Verifica el estado en tiempo real de una cerradura.
 */
router.post('/:id/verify', async (req: Request, res: Response) => {
  const deviceId = req.params.id as string;
  try {
    const result = await pool.query(
      `SELECT id, ubicacion, zona_piso, direccion_ip, mac_address,
              estado_conexion, ultimo_heartbeat, propietario_id, ${SQL_ESTADO_EFECTIVO}
       FROM dispositivos_cerradura WHERE id = $1`,
      [deviceId]
    );

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Dispositivo no encontrado' });
      return;
    }

    const device = result.rows[0];
    const wsConnected = isDeviceConnected(deviceId);

    res.json({
      id: device.id,
      ubicacion: device.ubicacion,
      estado_efectivo: device.estado_efectivo,
      websocket_conectado: wsConnected,
      ultimo_heartbeat: device.ultimo_heartbeat,
      propietario_id: device.propietario_id,
    });
  } catch (err) {
    res.status(500).json({ error: 'Error al verificar dispositivo' });
  }
});

/**
 * POST /api/v1/devices/:id/unlock
 * Control remoto desde la web: Envía orden de apertura instantánea vía WebSocket a la cerradura.
 */
router.post('/:id/unlock', async (req: Request, res: Response) => {
  const deviceId = req.params.id as string;
  const userId = req.usuario?.id;

  try {
    // Verificar permisos del usuario sobre el dispositivo
    const permCheck = await pool.query(
      `SELECT d.id FROM dispositivos_cerradura d
       LEFT JOIN permisos p ON p.dispositivo_id = d.id AND p.usuario_id = $1 AND p.activo = TRUE
       WHERE d.id = $2 AND (d.propietario_id = $1 OR p.id IS NOT NULL OR $3 = 'ADMIN')`,
      [userId, deviceId, req.usuario?.rol]
    );

    if (permCheck.rows.length === 0) {
      res.status(403).json({ error: 'No tienes autorización para controlar esta cerradura' });
      return;
    }

    const wsSent = sendToDevice(deviceId, {
      command: 'UNLOCK',
      solicitado_por: userId,
      timestamp: new Date(),
    });

    // Registrar apertura remota en auditoría y logs
    await pool.query(
      `INSERT INTO logs_acceso (dispositivo_id, uid_leido, usuario_id, evento, razon)
       VALUES ($1, 'WEB_REMOTE', $2, 'PERMITIDO', 'Desbloqueo remoto desde aplicación web')`,
      [deviceId, userId]
    );

    broadcastToWeb('remote_unlock', { deviceId, usuario_id: userId, timestamp: new Date() });

    res.json({
      ok: true,
      mensaje: wsSent ? 'Comando de apertura enviado a la cerradura vía WebSocket' : 'Cerradura notificada (modo fallback HTTP)',
      websocket_enviado: wsSent,
    });
  } catch (err) {
    console.error('[DEVICES] Error en unlock remoto:', err);
    res.status(500).json({ error: 'Error al enviar orden de desbloqueo' });
  }
});

// GET /api/v1/devices (General / Admin)
router.get('/', async (req: Request, res: Response) => {
  try {
    const result = await pool.query(
      `SELECT id, ubicacion, zona_piso, direccion_ip, mac_address,
              estado_conexion, ultimo_heartbeat, propietario_id, ${SQL_ESTADO_EFECTIVO}
       FROM dispositivos_cerradura ORDER BY ubicacion`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('[DEVICES] Error al listar:', err);
    res.status(500).json({ error: 'Error al listar dispositivos' });
  }
});

// GET /api/v1/devices/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const result = await pool.query(
      `SELECT id, ubicacion, zona_piso, direccion_ip, mac_address,
              estado_conexion, ultimo_heartbeat, propietario_id, ${SQL_ESTADO_EFECTIVO}
       FROM dispositivos_cerradura WHERE id = $1`,
      [req.params.id]
    );
    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Dispositivo no encontrado' });
      return;
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener dispositivo' });
  }
});

// POST /api/v1/devices (Admin)
router.post('/', requireRole('ADMIN'), async (req: Request, res: Response) => {
  const { id, ubicacion, zona_piso, direccion_ip, mac_address } = req.body;

  if (!id || !ubicacion || !zona_piso || !direccion_ip || !mac_address) {
    res.status(400).json({ error: 'id, ubicacion, zona_piso, direccion_ip y mac_address son obligatorios' });
    return;
  }

  try {
    const claveSecreta = crypto.randomBytes(24).toString('hex');
    const claveHash = await bcrypt.hash(claveSecreta, 10);

    const result = await pool.query(
      `INSERT INTO dispositivos_cerradura (id, ubicacion, zona_piso, direccion_ip, mac_address, clave_secreta_hash)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, ubicacion, zona_piso, direccion_ip, mac_address, estado_conexion`,
      [id, ubicacion, zona_piso, direccion_ip, mac_address, claveHash]
    );

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'CREAR_DISPOSITIVO',
        payload: { dispositivo_id: id, ubicacion },
        ip: req.ip,
      });
    }

    res.status(201).json({
      dispositivo: result.rows[0],
      clave_secreta: claveSecreta,
      aviso: 'Guarda esta clave ahora: no se puede volver a consultar.',
    });
  } catch (err: any) {
    if (err.code === '23505') {
      res.status(409).json({ error: 'Ya existe un dispositivo con ese id o MAC' });
      return;
    }
    console.error('[DEVICES] Error al crear:', err);
    res.status(500).json({ error: 'Error al crear dispositivo' });
  }
});

// PUT /api/v1/devices/:id
router.put('/:id', async (req: Request, res: Response) => {
  const { ubicacion, zona_piso, direccion_ip, estado_conexion } = req.body;
  const userId = req.usuario?.id;

  try {
    const devCheck = await pool.query(`SELECT propietario_id FROM dispositivos_cerradura WHERE id = $1`, [req.params.id]);
    if (devCheck.rows.length === 0) {
      res.status(404).json({ error: 'Dispositivo no encontrado' });
      return;
    }

    if (req.usuario?.rol !== 'ADMIN' && devCheck.rows[0].propietario_id !== userId) {
      res.status(403).json({ error: 'No tienes permisos para editar este dispositivo' });
      return;
    }

    const result = await pool.query(
      `UPDATE dispositivos_cerradura SET
         ubicacion = COALESCE($1, ubicacion),
         zona_piso = COALESCE($2, zona_piso),
         direccion_ip = COALESCE($3, direccion_ip),
         estado_conexion = COALESCE($4, estado_conexion)
       WHERE id = $5
       RETURNING id, ubicacion, zona_piso, direccion_ip, mac_address, estado_conexion`,
      [ubicacion, zona_piso, direccion_ip, estado_conexion, req.params.id]
    );

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'EDITAR_DISPOSITIVO',
        payload: { dispositivo_id: req.params.id, cambios: req.body },
        ip: req.ip,
      });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error al editar dispositivo' });
  }
});

// POST /api/v1/devices/:id/rotate-key
router.post('/:id/rotate-key', async (req: Request, res: Response) => {
  const userId = req.usuario?.id;
  try {
    const devCheck = await pool.query(`SELECT propietario_id FROM dispositivos_cerradura WHERE id = $1`, [req.params.id]);
    if (devCheck.rows.length === 0) {
      res.status(404).json({ error: 'Dispositivo no encontrado' });
      return;
    }

    if (req.usuario?.rol !== 'ADMIN' && devCheck.rows[0].propietario_id !== userId) {
      res.status(403).json({ error: 'No tienes permisos para rotar la clave de esta cerradura' });
      return;
    }

    const claveSecreta = crypto.randomBytes(24).toString('hex');
    const claveHash = await bcrypt.hash(claveSecreta, 10);

    await pool.query(`UPDATE dispositivos_cerradura SET clave_secreta_hash = $1 WHERE id = $2`, [claveHash, req.params.id]);

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'ROTAR_CLAVE_DISPOSITIVO',
        payload: { dispositivo_id: req.params.id },
        ip: req.ip,
      });
    }

    res.json({ clave_secreta: claveSecreta, aviso: 'Actualiza el firmware del nodo con esta nueva clave.' });
  } catch (err) {
    res.status(500).json({ error: 'Error al rotar la clave' });
  }
});

// DELETE /api/v1/devices/:id
router.delete('/:id', async (req: Request, res: Response) => {
  const userId = req.usuario?.id;
  try {
    const devCheck = await pool.query(`SELECT propietario_id FROM dispositivos_cerradura WHERE id = $1`, [req.params.id]);
    if (devCheck.rows.length === 0) {
      res.status(404).json({ error: 'Dispositivo no encontrado' });
      return;
    }

    if (req.usuario?.rol !== 'ADMIN' && devCheck.rows[0].propietario_id !== userId) {
      res.status(403).json({ error: 'No tienes permisos para eliminar este dispositivo' });
      return;
    }

    await pool.query(`DELETE FROM dispositivos_cerradura WHERE id = $1`, [req.params.id]);

    if (req.usuario) {
      await registrarAuditoria({
        adminId: req.usuario.id,
        accion: 'ELIMINAR_DISPOSITIVO',
        payload: { dispositivo_id: req.params.id },
        ip: req.ip,
      });
    }

    res.json({ ok: true, mensaje: 'Dispositivo eliminado' });
  } catch (err) {
    res.status(409).json({ error: 'No se puede eliminar: tiene permisos o registros asociados' });
  }
});

export default router;
