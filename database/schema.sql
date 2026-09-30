-- Habilitar extensión para generación de UUID v4
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. TABLA: usuarios
CREATE TABLE usuarios (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  nombre VARCHAR(100) NOT NULL,
  apellido VARCHAR(100) NOT NULL,
  correo VARCHAR(150) UNIQUE NOT NULL,
  departamento VARCHAR(80) NOT NULL,
  estado VARCHAR(20) NOT NULL DEFAULT 'ACTIVO' CHECK (estado IN ('ACTIVO', 'INACTIVO', 'SUSPENDIDO')),
  password_hash VARCHAR(255), -- NULL = usuario sin acceso al Dashboard (solo credencial física)
  rol VARCHAR(20) NOT NULL DEFAULT 'USUARIO' CHECK (rol IN ('ADMIN', 'OPERADOR', 'USUARIO')),
  creado_en TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. TABLA: credenciales
CREATE TABLE credenciales (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  uid_hex VARCHAR(32) UNIQUE NOT NULL,
  tipo VARCHAR(20) NOT NULL DEFAULT 'RFID_13.56MHZ',
  estado VARCHAR(20) NOT NULL DEFAULT 'ACTIVA' CHECK (estado IN ('ACTIVA', 'REVOCADA', 'SUSPENDIDA')),
  usuario_id UUID NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  emitida_en TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expira_en TIMESTAMPTZ NOT NULL,
  CONSTRAINT chk_fechas_credencial CHECK (expira_en > emitida_en)
);

-- 3. TABLA: dispositivos_cerradura (con propietario para autoregistro/control web)
CREATE TABLE dispositivos_cerradura (
  id VARCHAR(32) PRIMARY KEY, -- Ej: "ESP32-PUERTA-PRINCIPAL"
  ubicacion VARCHAR(150) NOT NULL,
  zona_piso VARCHAR(50) NOT NULL,
  direccion_ip VARCHAR(45) NOT NULL,
  mac_address VARCHAR(17) UNIQUE NOT NULL,
  clave_secreta_hash VARCHAR(64) NOT NULL,
  estado_conexion VARCHAR(20) NOT NULL DEFAULT 'OFFLINE' CHECK (estado_conexion IN ('ONLINE', 'OFFLINE', 'MANTENIMIENTO')),
  ultimo_heartbeat TIMESTAMPTZ,
  propietario_id UUID REFERENCES usuarios(id) ON DELETE SET NULL
);

-- 4. TABLA: permisos
CREATE TABLE permisos (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  usuario_id UUID NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  dispositivo_id VARCHAR(32) NOT NULL REFERENCES dispositivos_cerradura(id) ON DELETE CASCADE,
  hora_inicio TIME NOT NULL DEFAULT '00:00:00',
  hora_fin TIME NOT NULL DEFAULT '23:59:59',
  dias_semana SMALLINT[] NOT NULL DEFAULT '{1,2,3,4,5,6,7}', -- 1: Lunes, 7: Domingo
  fecha_limite TIMESTAMPTZ NOT NULL,
  activo BOOLEAN NOT NULL DEFAULT TRUE,
  CONSTRAINT chk_rango_horas CHECK (hora_fin > hora_inicio)
);

-- 5. TABLA PARTICIONADA: logs_acceso
CREATE TABLE logs_acceso (
  id BIGSERIAL,
  dispositivo_id VARCHAR(32) NOT NULL REFERENCES dispositivos_cerradura(id),
  uid_leido VARCHAR(32) NOT NULL,
  usuario_id UUID REFERENCES usuarios(id) ON DELETE SET NULL,
  evento VARCHAR(30) NOT NULL CHECK (evento IN (
    'PERMITIDO', 'DENEGADO', 'OFFLINE_PERMITIDO', 'OFFLINE_DENEGADO', 'ALERTA_INTRUSION'
  )),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  razon VARCHAR(100) NOT NULL,
  PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Particiones
CREATE TABLE logs_acceso_2026_m09 PARTITION OF logs_acceso
  FOR VALUES FROM ('2026-09-01 00:00:00+00') TO ('2026-10-01 00:00:00+00');

CREATE TABLE logs_acceso_2026_m10 PARTITION OF logs_acceso
  FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');

-- 6. TABLA: sesiones_audit_admin
CREATE TABLE sesiones_audit_admin (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  admin_id UUID NOT NULL REFERENCES usuarios(id),
  accion VARCHAR(50) NOT NULL,
  payload_json JSONB NOT NULL,
  ip_origen VARCHAR(45) NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ÍNDICES OPTIMIZADOS
CREATE INDEX idx_credenciales_uid ON credenciales USING btree (uid_hex);
CREATE INDEX idx_permisos_lookup ON permisos USING btree (usuario_id, dispositivo_id, activo);
CREATE INDEX idx_logs_timestamp ON logs_acceso USING btree (timestamp DESC);
CREATE INDEX idx_dispositivos_propietario ON dispositivos_cerradura USING btree (propietario_id);
