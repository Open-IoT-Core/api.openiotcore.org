import { Request, Response, NextFunction } from 'express';
import passport from 'passport';
import { UserPayload, UserRole } from '../types';

/**
 * Exige un JWT válido usando Passport JWT Strategy.
 * Adjunta el usuario decodificado tanto a req.user como a req.usuario.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  passport.authenticate('jwt', { session: false }, (err: any, user: UserPayload | false, info: any) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.status(401).json({ error: 'Token de autenticación requerido o inválido' });
    }
    req.user = user;
    req.usuario = user;
    next();
  })(req, res, next);
}

/**
 * Exige que el usuario autenticado tenga uno de los roles indicados.
 * Uso: requireRole('ADMIN') o requireRole('ADMIN', 'OPERADOR')
 */
export function requireRole(...rolesPermitidos: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const usuario = req.usuario || (req.user as UserPayload);
    if (!usuario || !rolesPermitidos.includes(usuario.rol)) {
      res.status(403).json({ error: 'No tienes permisos para esta acción' });
      return;
    }
    next();
  };
}
