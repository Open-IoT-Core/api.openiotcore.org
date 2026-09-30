import { Request } from 'express';

export type UserRole = 'ADMIN' | 'OPERADOR' | 'USUARIO';
export type UserStatus = 'ACTIVO' | 'INACTIVO' | 'SUSPENDIDO';

export interface UserPayload {
  id: string;
  correo: string;
  rol: UserRole;
  nombre?: string;
  apellido?: string;
}

export interface UserRow {
  id: string;
  nombre: string;
  apellido: string;
  correo: string;
  departamento: string;
  estado: UserStatus;
  rol: UserRole;
  password_hash?: string | null;
  creado_en?: Date;
}

declare global {
  namespace Express {
    interface User extends UserPayload {}
    interface Request {
      usuario?: UserPayload;
    }
  }
}
