import dotenv from 'dotenv';
dotenv.config();

import express, { Request, Response } from 'express';
import http from 'http';
import cors from 'cors';
import helmet from 'helmet';
import passport, { configurePassport } from './config/passport';
import { apiLimiter } from './middleware/rateLimit';
import { initWebSocketServer } from './websocket/server';

import accessRoutes from './routes/access';
import authRoutes from './routes/auth';
import usersRoutes from './routes/users';
import credentialsRoutes from './routes/credentials';
import devicesRoutes from './routes/devices';
import permissionsRoutes from './routes/permissions';
import logsRoutes from './routes/logs';
import dashboardRoutes from './routes/dashboard';

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 4000;

// Habilitar trust proxy para reverse proxies (Docker, Nginx, Cloudflare, Pterodactyl)
// Necesario para que express-rate-limit pueda identificar las IP reales tras la cabecera X-Forwarded-For
app.set('trust proxy', 1);

if (!process.env.JWT_SECRET) {
  console.warn('[SERVER] ADVERTENCIA: JWT_SECRET no está definido en el entorno.');
}

// Inicializar Passport y WebSockets
configurePassport();
initWebSocketServer(server);

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(passport.initialize());

// Rate Limiter general para la API
app.use('/api', apiLimiter);

// Health check simple
app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({ status: 'ok', service: 'openiotcore-api', runtime: 'bun', websockets: 'enabled' });
});

// Rutas públicas / Auth / Acceso ESP32
app.use('/api/v1/access', accessRoutes);
app.use('/api/v1/auth', authRoutes);

// Rutas protegidas (requireAuth se aplica dentro de cada router)
app.use('/api/v1/users', usersRoutes);
app.use('/api/v1/credentials', credentialsRoutes);
app.use('/api/v1/devices', devicesRoutes);
app.use('/api/v1/permissions', permissionsRoutes);
app.use('/api/v1/logs', logsRoutes);
app.use('/api/v1/access/logs', logsRoutes);
app.use('/api/v1/dashboard', dashboardRoutes);

app.use((req: Request, res: Response) => {
  res.status(404).json({ error: 'Ruta no encontrada' });
});

server.listen(PORT, () => {
  console.log(`[SERVER] OpenIoTCore API (Bun + TS + WebSockets) escuchando en el puerto ${PORT}`);
});

export default app;
