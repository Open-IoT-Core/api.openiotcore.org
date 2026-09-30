import pool from '../config/db';

export interface AuditoriaParams {
  adminId: string;
  accion: string;
  payload?: Record<string, any>;
  ip?: string;
}

export async function registrarAuditoria({ adminId, accion, payload, ip }: AuditoriaParams): Promise<void> {
  try {
    await pool.query(
      `INSERT INTO sesiones_audit_admin (admin_id, accion, payload_json, ip_origen)
       VALUES ($1, $2, $3, $4)`,
      [adminId, accion, JSON.stringify(payload || {}), ip || 'desconocida']
    );
  } catch (err) {
    // La auditoría nunca debe tumbar la petición principal: solo se registra el error.
    console.error('[AUDIT] No se pudo registrar la auditoría:', err);
  }
}
