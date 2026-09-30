import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import bcrypt from 'bcryptjs';
import pool from './db';
import { UserPayload, UserRow } from '../types';

export function configurePassport(): void {
  // Configurar Estrategia Local (Correo + Contraseña)
  passport.use(
    new LocalStrategy(
      {
        usernameField: 'correo',
        passwordField: 'clave',
      },
      async (correo, clave, done) => {
        try {
          const result = await pool.query<UserRow>(
            `SELECT id, nombre, apellido, correo, rol, estado, password_hash
             FROM usuarios WHERE correo = $1`,
            [correo]
          );

          if (result.rows.length === 0) {
            return done(null, false, { message: 'Credenciales inválidas' });
          }

          const usuario = result.rows[0];

          if (!usuario.password_hash) {
            return done(null, false, { message: 'Este usuario no tiene acceso al Dashboard' });
          }

          if (usuario.estado !== 'ACTIVO') {
            return done(null, false, { message: 'Usuario inactivo o suspendido' });
          }

          const claveValida = await bcrypt.compare(clave, usuario.password_hash);
          if (!claveValida) {
            return done(null, false, { message: 'Credenciales inválidas' });
          }

          const userPayload: UserPayload = {
            id: usuario.id,
            correo: usuario.correo,
            rol: usuario.rol,
            nombre: usuario.nombre,
            apellido: usuario.apellido,
          };

          return done(null, userPayload);
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  // Configurar Estrategia JWT para protección de rutas
  const secret = process.env.JWT_SECRET || 'secret';
  passport.use(
    new JwtStrategy(
      {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: secret,
      },
      async (jwtPayload: UserPayload, done) => {
        try {
          if (!jwtPayload || !jwtPayload.id) {
            return done(null, false);
          }
          return done(null, jwtPayload);
        } catch (err) {
          return done(err, false);
        }
      }
    )
  );
}

export default passport;
