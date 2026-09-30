import { Router, Request, Response } from 'express';
import pool from '../config/db';
import { broadcastToWeb } from '../websocket/server';

const router = Router();

/**
 * POST /api/v1/access/validate
 * Body: { device_id: string, uid_hex: string }
 * Respuesta: { access_granted: boolean, reason: string }
 */
router.post('/validate', async (req: Request, res: Response) => {
  const { device_id, uid_hex } = req.body;

  if (!device_id || !uid_hex) {
    res.status(400).json({ error: 'device_id y uid_hex son obligatorios' });
    return;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Auto-registro / Heartbeat del dispositivo para garantizar integridad de FK en logs_acceso
    await client.query(
      `INSERT INTO dispositivos_cerradura (id, ubicacion, estado_conexion, ultimo_heartbeat, direccion_ip)
       VALUES ($1, 'Pendiente de vinculación', 'ONLINE', CURRENT_TIMESTAMP, COALESCE($2, '0.0.0.0'))
       ON CONFLICT (id) DO UPDATE SET
         estado_conexion = 'ONLINE',
         ultimo_heartbeat = CURRENT_TIMESTAMP,
         direccion_ip = COALESCE($2, dispositivos_cerradura.direccion_ip)`,
      [device_id, req.ip]
    );

    const credQuery = `
      SELECT c.id AS credencial_id, c.estado AS estado_cred,
             u.id AS usuario_id, u.nombre, u.apellido, u.estado AS estado_usr
      FROM credenciales c
      JOIN usuarios u ON c.usuario_id = u.id
      WHERE c.uid_hex = $1;
    `;
    const credRes = await client.query(credQuery, [uid_hex]);

    if (credRes.rows.length === 0) {
      await client.query(
        `INSERT INTO logs_acceso (dispositivo_id, uid_leido, evento, razon)
         VALUES ($1, $2, 'DENEGADO', 'Tarjeta no registrada')`,
        [device_id, uid_hex]
      );
      await client.query('COMMIT');

      broadcastToWeb('access_event', {
        device_id,
        uid_hex,
        evento: 'DENEGADO',
        razon: 'Tarjeta no registrada',
        timestamp: new Date(),
      });

      res.status(200).json({ access_granted: false, reason: 'Tarjeta no registrada' });
      return;
    }

    const { usuario_id, nombre, apellido, estado_cred, estado_usr } = credRes.rows[0];

    if (estado_cred !== 'ACTIVA' || estado_usr !== 'ACTIVO') {
      await client.query(
        `INSERT INTO logs_acceso (dispositivo_id, uid_leido, usuario_id, evento, razon)
         VALUES ($1, $2, $3, 'DENEGADO', 'Credencial o usuario inactivo')`,
        [device_id, uid_hex, usuario_id]
      );
      await client.query('COMMIT');

      broadcastToWeb('access_event', {
        device_id,
        uid_hex,
        usuario_id,
        nombre,
        apellido,
        evento: 'DENEGADO',
        razon: 'Credencial inactiva',
        timestamp: new Date(),
      });

      res.status(200).json({ access_granted: false, reason: 'Credencial inactiva' });
      return;
    }

    const permQuery = `
      SELECT id FROM permisos
      WHERE usuario_id = $1 AND dispositivo_id = $2 AND activo = TRUE
        AND CURRENT_TIME BETWEEN hora_inicio AND hora_fin
        AND fecha_limite >= CURRENT_TIMESTAMP;
    `;
    const permRes = await client.query(permQuery, [usuario_id, device_id]);

    if (permRes.rows.length > 0) {
      await client.query(
        `INSERT INTO logs_acceso (dispositivo_id, uid_leido, usuario_id, evento, razon)
         VALUES ($1, $2, $3, 'PERMITIDO', 'Acceso autorizado')`,
        [device_id, uid_hex, usuario_id]
      );
      await client.query('COMMIT');

      broadcastToWeb('access_event', {
        device_id,
        uid_hex,
        usuario_id,
        nombre,
        apellido,
        evento: 'PERMITIDO',
        razon: 'Acceso autorizado',
        timestamp: new Date(),
      });

      res.status(200).json({ access_granted: true, reason: 'Acceso autorizado' });
      return;
    }

    await client.query(
      `INSERT INTO logs_acceso (dispositivo_id, uid_leido, usuario_id, evento, razon)
       VALUES ($1, $2, $3, 'DENEGADO', 'Sin permiso en este horario/dispositivo')`,
      [device_id, uid_hex, usuario_id]
    );
    await client.query('COMMIT');

    broadcastToWeb('access_event', {
      device_id,
      uid_hex,
      usuario_id,
      nombre,
      apellido,
      evento: 'DENEGADO',
      razon: 'Sin permiso para esta puerta/horario',
      timestamp: new Date(),
    });

    res.status(200).json({ access_granted: false, reason: 'Sin permiso para esta puerta/horario' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[ACCESS] Error en validación:', err);
    res.status(500).json({ error: 'Error interno al procesar validación' });
  } finally {
    client.release();
  }
});

/**
 * GET /api/v1/access/offline-sync
 * Query: ?device_id=ESP32-000000000000
 */
router.get('/offline-sync', async (req: Request, res: Response) => {
  const deviceId = req.query.device_id as string;

  if (!deviceId) {
    res.status(400).json({ error: 'device_id es obligatorio para la sincronización offline' });
    return;
  }

  try {
    const result = await pool.query(
      `SELECT DISTINCT
         c.uid_hex,
         c.usuario_id,
         u.nombre,
         u.apellido,
         p.hora_inicio,
         p.hora_fin,
         p.dias_semana,
         p.fecha_limite
       FROM permisos p
       JOIN usuarios u ON u.id = p.usuario_id AND u.estado = 'ACTIVO'
       JOIN credenciales c ON c.usuario_id = u.id AND c.estado = 'ACTIVA'
       WHERE p.dispositivo_id = $1
         AND p.activo = TRUE
         AND p.fecha_limite >= CURRENT_TIMESTAMP`,
      [deviceId]
    );

    res.json({
      dispositivo_id: deviceId,
      sincronizado_en: new Date(),
      total_credenciales: result.rows.length,
      credenciales_autorizadas: result.rows,
    });
  } catch (err) {
    console.error('[ACCESS] Error en sincronización offline:', err);
    res.status(500).json({ error: 'Error al generar paquete de sincronización offline' });
  }
});

export default router;
