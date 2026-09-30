import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import pool from '../config/db';
import { requireAuth } from '../middleware/auth';
import { authLimiter } from '../middleware/rateLimit';
import { UserPayload, UserRow } from '../types';

const router = Router();

/**
 * POST /api/v1/auth/register
 * Body: { nombre, apellido, correo, clave, departamento, rol? }
 * Registro público o autoconfigurado de nuevos usuarios / administradores.
 */
router.post('/register', authLimiter, async (req: Request, res: Response) => {
  const { nombre, apellido, correo, clave, departamento, rol } = req.body;

  if (!nombre || !apellido || !correo || !clave || !departamento) {
    res.status(400).json({ error: 'nombre, apellido, correo, clave y departamento son obligatorios' });
    return;
  }

  if (clave.length < 6) {
    res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    return;
  }

  try {
    const passwordHash = await bcrypt.hash(clave, 10);
    const userRole = rol && ['ADMIN', 'OPERADOR', 'USUARIO'].includes(rol) ? rol : 'USUARIO';

    const result = await pool.query<UserRow>(
      `INSERT INTO usuarios (nombre, apellido, correo, departamento, rol, password_hash)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, nombre, apellido, correo, departamento, estado, rol, creado_en`,
      [nombre, apellido, correo, departamento, userRole, passwordHash]
    );

    const usuario = result.rows[0];
    const secret = process.env.JWT_SECRET || 'secret';
    const expiresIn = process.env.JWT_EXPIRES_IN || '8h';

    const tokenPayload: UserPayload = {
      id: usuario.id,
      correo: usuario.correo,
      rol: usuario.rol,
      nombre: usuario.nombre,
      apellido: usuario.apellido,
    };

    const token = jwt.sign(tokenPayload, secret, { expiresIn: expiresIn as any });

    res.status(201).json({
      mensaje: 'Usuario registrado exitosamente',
      token,
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        apellido: usuario.apellido,
        correo: usuario.correo,
        departamento: usuario.departamento,
        rol: usuario.rol,
      },
    });
  } catch (err: any) {
    if (err.code === '23505') {
      res.status(409).json({ error: 'Ya existe un usuario registrado con este correo' });
      return;
    }
    console.error('[AUTH] Error en registro:', err);
    res.status(500).json({ error: 'Error interno al registrar usuario' });
  }
});

/**
 * POST /api/v1/auth/login
 * Body: { correo, clave }
 * Inicia sesión utilizando Passport Local Strategy.
 */
router.post('/login', authLimiter, (req: Request, res: Response, next) => {
  const { correo, clave } = req.body;
  if (!correo || !clave) {
    res.status(400).json({ error: 'correo y clave son obligatorios' });
    return;
  }

  passport.authenticate('local', { session: false }, (err: any, user: UserPayload | false, info: any) => {
    if (err) {
      console.error('[AUTH] Error en login:', err);
      return res.status(500).json({ error: 'Error interno al iniciar sesión' });
    }

    if (!user) {
      return res.status(401).json({ error: info?.message || 'Credenciales inválidas' });
    }

    const secret = process.env.JWT_SECRET || 'secret';
    const expiresIn = process.env.JWT_EXPIRES_IN || '8h';

    const token = jwt.sign(
      { id: user.id, correo: user.correo, rol: user.rol },
      secret,
      { expiresIn: expiresIn as any }
    );

    res.json({
      token,
      usuario: {
        id: user.id,
        nombre: user.nombre,
        apellido: user.apellido,
        correo: user.correo,
        rol: user.rol,
      },
    });
  })(req, res, next);
});

/**
 * GET /api/v1/auth/me
 * Obtiene el perfil del usuario autenticado actualmente.
 */
router.get('/me', requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = req.usuario?.id;
    const result = await pool.query<UserRow>(
      `SELECT id, nombre, apellido, correo, departamento, estado, rol, creado_en
       FROM usuarios WHERE id = $1`,
      [userId]
    );

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Usuario no encontrado' });
      return;
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('[AUTH] Error en /me:', err);
    res.status(500).json({ error: 'Error al obtener datos del perfil' });
  }
});

/**
 * PUT /api/v1/auth/me
 * Actualiza el perfil del usuario autenticado actualmente.
 */
router.put('/me', requireAuth, async (req: Request, res: Response) => {
  const userId = req.usuario?.id;
  const { nombre, apellido, departamento } = req.body;

  try {
    const result = await pool.query<UserRow>(
      `UPDATE usuarios SET
         nombre = COALESCE($1, nombre),
         apellido = COALESCE($2, apellido),
         departamento = COALESCE($3, departamento)
       WHERE id = $4
       RETURNING id, nombre, apellido, correo, departamento, estado, rol, creado_en`,
      [nombre, apellido, departamento, userId]
    );

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Usuario no encontrado' });
      return;
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('[AUTH] Error actualizando perfil /me:', err);
    res.status(500).json({ error: 'Error al actualizar el perfil' });
  }
});

/**
 * POST /api/v1/auth/change-password
 * Cambia la contraseña del usuario autenticado.
 */
router.post('/change-password', requireAuth, async (req: Request, res: Response) => {
  const userId = req.usuario?.id;
  const { claveActual, claveNueva } = req.body;

  if (!claveActual || !claveNueva) {
    res.status(400).json({ error: 'claveActual y claveNueva son obligatorios' });
    return;
  }

  if (claveNueva.length < 6) {
    res.status(400).json({ error: 'La clave nueva debe tener al menos 6 caracteres' });
    return;
  }

  try {
    const userRes = await pool.query<UserRow>(
      `SELECT password_hash FROM usuarios WHERE id = $1`,
      [userId]
    );

    if (userRes.rows.length === 0 || !userRes.rows[0].password_hash) {
      res.status(404).json({ error: 'Usuario no encontrado' });
      return;
    }

    const valida = await bcrypt.compare(claveActual, userRes.rows[0].password_hash);
    if (!valida) {
      res.status(401).json({ error: 'La contraseña actual es incorrecta' });
      return;
    }

    const nuevoHash = await bcrypt.hash(claveNueva, 10);
    await pool.query(`UPDATE usuarios SET password_hash = $1 WHERE id = $2`, [nuevoHash, userId]);

    res.json({ ok: true, mensaje: 'Contraseña actualizada con éxito' });
  } catch (err) {
    console.error('[AUTH] Error al cambiar contraseña:', err);
    res.status(500).json({ error: 'Error al cambiar la contraseña' });
  }
});

export default router;
