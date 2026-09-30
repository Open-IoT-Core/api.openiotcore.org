import { Router, Request, Response } from 'express';
import pool from '../config/db';
import { requireAuth } from '../middleware/auth';

const router = Router();

router.use(requireAuth);

// GET /api/v1/dashboard/summary
router.get('/summary', async (req: Request, res: Response) => {
  try {
    const metricasHoy = await pool.query(`
      SELECT
        COUNT(*)::int AS entradas_hoy,
        COUNT(*) FILTER (WHERE evento IN ('PERMITIDO', 'OFFLINE_PERMITIDO'))::int AS permitidos_hoy,
        COUNT(*) FILTER (WHERE evento IN ('DENEGADO', 'OFFLINE_DENEGADO', 'ALERTA_INTRUSION'))::int AS denegados_hoy
      FROM logs_acceso
      WHERE timestamp >= CURRENT_DATE
    `);

    const dispositivos = await pool.query(`
      SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE ultimo_heartbeat > NOW() - INTERVAL '2 minutes')::int AS online
      FROM dispositivos_cerradura
    `);

    const actividadReciente = await pool.query(`
      SELECT l.timestamp, d.ubicacion, l.uid_leido, u.nombre, u.apellido, l.evento
      FROM logs_acceso l
      LEFT JOIN dispositivos_cerradura d ON d.id = l.dispositivo_id
      LEFT JOIN usuarios u ON u.id = l.usuario_id
      ORDER BY l.timestamp DESC
      LIMIT 15
    `);

    res.json({
      entradas_hoy: metricasHoy.rows[0].entradas_hoy,
      permitidos_hoy: metricasHoy.rows[0].permitidos_hoy,
      denegados_hoy: metricasHoy.rows[0].denegados_hoy,
      dispositivos: dispositivos.rows[0],
      actividad_reciente: actividadReciente.rows,
    });
  } catch (err) {
    console.error('[DASHBOARD] Error al calcular resumen:', err);
    res.status(500).json({ error: 'Error al calcular el resumen del dashboard' });
  }
});

export default router;
