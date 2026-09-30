# OpenIoTCore API

API del Sistema de Control de Acceso Físico Inteligente. Pensada para vivir en
`https://api.openiotcore.org`.

## Puesta en marcha (local, con Docker)

```bash
cp .env.example .env        # y edita JWT_SECRET, contraseñas, etc.
docker compose up -d        # levanta PostgreSQL + la API
npm install                 # solo si vas a correr scripts fuera del contenedor
npm run create-admin -- admin@openiotcore.org "unaClaveSegura123" Ada Lovelace
```

Sin Docker: crea la base de datos, corre `database/schema.sql`, configura
`.env` con tus credenciales de PostgreSQL y luego `npm install && npm start`.

## Autenticación

Casi todas las rutas (excepto `/api/v1/access/*` y `/api/v1/auth/login`) piden
un JWT:

```
Authorization: Bearer <token>
```

El token se obtiene en `POST /api/v1/auth/login` y solo funciona para
usuarios creados con contraseña (rol `ADMIN` u `OPERADOR`). El primer admin se
crea con `npm run create-admin` (ver arriba); desde el Dashboard, un `ADMIN`
puede crear operadores adicionales en `POST /api/v1/users`.

## Endpoints

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| POST | `/api/v1/access/validate` | Ninguna (nodo ESP32) | Valida una tarjeta y registra el log |
| POST | `/api/v1/auth/login` | Ninguna | Login de operador/admin, devuelve JWT |
| GET/POST | `/api/v1/users` | JWT | Listar / crear usuarios |
| GET/PUT/DELETE | `/api/v1/users/:id` | JWT | Ver / editar / desactivar usuario |
| GET/POST | `/api/v1/credentials` | JWT | Listar / vincular tarjetas RFID |
| PATCH | `/api/v1/credentials/:id/revoke` | JWT | Revocar una tarjeta |
| PATCH | `/api/v1/credentials/:id/reactivate` | JWT | Reactivar una tarjeta |
| DELETE | `/api/v1/credentials/:id` | JWT | Eliminar una tarjeta |
| GET/POST | `/api/v1/devices` | JWT | Listar / registrar nodos ESP32 |
| PUT | `/api/v1/devices/:id` | JWT (ADMIN) | Editar un nodo |
| POST | `/api/v1/devices/:id/rotate-key` | JWT (ADMIN) | Generar nueva clave del nodo |
| DELETE | `/api/v1/devices/:id` | JWT (ADMIN) | Eliminar un nodo |
| GET/POST | `/api/v1/permissions` | JWT | Listar / crear reglas de horario |
| PUT/PATCH/DELETE | `/api/v1/permissions/:id` | JWT | Editar / pausar / eliminar un permiso |
| GET | `/api/v1/logs` | JWT | Auditoría forense con filtros |
| GET | `/api/v1/logs/export` | JWT | Exporta los mismos filtros a CSV |
| GET | `/api/v1/dashboard/summary` | JWT | Métricas del panel principal |

Filtros disponibles en `/api/v1/logs` (y `/export`): `desde`, `hasta`
(timestamps ISO), `evento`, `dispositivo_id`, `uid`, `pagina`, `limite`.

## Pendiente / próximos pasos sugeridos

- Servir esta API detrás de HTTPS real (Let's Encrypt / Nginx o el proxy de
  tu proveedor) antes de que el ESP32 dependa de ella en producción.
- Reemplazar `client.setInsecure()` en el firmware por `setCACert()` una vez
  el certificado esté activo.
- Autenticar las peticiones de `/access/validate` con la clave secreta del
  dispositivo (ya se genera en `POST /api/v1/devices`, falta verificarla en
  el middleware de esa ruta).
