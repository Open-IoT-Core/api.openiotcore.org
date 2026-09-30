import { Router, Request, Response } from 'express';
import pool from '../config/db';
import { requireAuth } from '../middleware/auth';

const router = Router();

router.use(requireAuth);

function construirFiltro(query: any) {
  const { desde, hasta, evento, dispositivo_id, uid } = query;
  const condiciones: string[] = [];
  const params: any[] = [];

  if (desde) { params.push(desde); condiciones.push(`l.timestamp >= $${params.length}`); }
  if (hasta) { params.push(hasta); condiciones.push(`l.timestamp <= $${params.length}`); }
  if (evento) { params.push(evento); condiciones.push(`l.evento = $${params.length}`); }
  if (dispositivo_id) { params.push(dispositivo_id); condiciones.push(`l.dispositivo_id = $${params.length}`); }
  if (uid) { params.push(`%${uid.toUpperCase()}%`); condiciones.push(`l.uid_leido ILIKE $${params.length}`); }

  const where = condiciones.length ? `WHERE ${condiciones.join(' AND ')}` : '';
  return { where, params };
}

// GET /api/v1/logs
router.get('/', async (req: Request, res: Response) => {
  const { where, params } = construirFiltro(req.query);
  const limite = Math.min(parseInt(req.query.limite as string) || 50, 200);
  const pagina = Math.max(parseInt(req.query.pagina as string) || 1, 1);
  const offset = (pagina - 1) * limite;

  try {
    const totalResult = await pool.query(
      `SELECT COUNT(*)::int AS total FROM logs_acceso l ${where}`,
      params
    );

    const dataResult = await pool.query(
      `SELECT l.id, l.timestamp, l.dispositivo_id, d.ubicacion, l.uid_leido,
              u.nombre, u.apellido, l.evento, l.razon
       FROM logs_acceso l
       LEFT JOIN dispositivos_cerradura d ON d.id = l.dispositivo_id
       LEFT JOIN usuarios u ON u.id = l.usuario_id
       ${where}
       ORDER BY l.timestamp DESC
       LIMIT ${limite} OFFSET ${offset}`,
      params
    );

    res.json({
      total: totalResult.rows[0].total,
      pagina,
      limite,
      resultados: dataResult.rows,
    });
  } catch (err) {
    console.error('[LOGS] Error al listar:', err);
    res.status(500).json({ error: 'Error al consultar los registros de auditoría' });
  }
});

// GET /api/v1/logs/export
router.get('/export', async (req: Request, res: Response) => {
  const { where, params } = construirFiltro(req.query);

  try {
    const result = await pool.query(
      `SELECT l.timestamp, l.dispositivo_id, d.ubicacion, l.uid_leido,
              u.nombre, u.apellido, l.evento, l.razon
       FROM logs_acceso l
       LEFT JOIN dispositivos_cerradura d ON d.id = l.dispositivo_id
       LEFT JOIN usuarios u ON u.id = l.usuario_id
       ${where}
       ORDER BY l.timestamp DESC
       LIMIT 10000`,
      params
    );

    const encabezados = ['fecha_hora', 'dispositivo_id', 'ubicacion', 'uid_leido', 'nombre', 'apellido', 'evento', 'razon'];
    const escaparCsv = (valor: any) => {
      if (valor === null || valor === undefined) return '';
      const texto = String(valor).replace(/"/g, '""');
      return /[",\n]/.test(texto) ? `"${texto}"` : texto;
    };

    const filas = result.rows.map((r: any) =>
      [r.timestamp ? r.timestamp.toISOString() : '', r.dispositivo_id, r.ubicacion, r.uid_leido, r.nombre, r.apellido, r.evento, r.razon]
        .map(escaparCsv)
        .join(',')
    );

    const csv = [encabezados.join(','), ...filas].join('\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="auditoria_openiotcore.csv"`);
    res.send(csv);
  } catch (err) {
    console.error('[LOGS] Error al exportar:', err);
    res.status(500).json({ error: 'Error al exportar los registros' });
  }
});

export default router;
