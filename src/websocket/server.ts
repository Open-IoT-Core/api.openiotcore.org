import { Server as HttpServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import jwt from 'jsonwebtoken';
import { UserPayload } from '../types';

export interface DeviceClient {
  deviceId: string;
  ws: WebSocket;
  connectedAt: Date;
}

export interface WebClient {
  userId: string;
  ws: WebSocket;
  connectedAt: Date;
}

const deviceClients = new Map<string, DeviceClient>();
const webClients = new Set<WebClient>();

export function initWebSocketServer(server: HttpServer): WebSocketServer {
  const wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', (ws: WebSocket, req) => {
    const url = new URL(req.url || '', `http://${req.headers.host || 'localhost'}`);
    const clientType = url.searchParams.get('type'); // 'device' | 'web'
    const token = url.searchParams.get('token');
    const deviceId = url.searchParams.get('deviceId');

    if (clientType === 'web') {
      if (!token) {
        ws.close(4001, 'Token de autenticación requerido');
        return;
      }
      try {
        const secret = process.env.JWT_SECRET || 'secret';
        const user = jwt.verify(token, secret) as UserPayload;
        const client: WebClient = { userId: user.id, ws, connectedAt: new Date() };
        webClients.add(client);

        ws.send(JSON.stringify({ event: 'connected', type: 'web', userId: user.id }));

        ws.on('message', (data) => {
          try {
            const msg = JSON.parse(data.toString());
            if (msg.action === 'ping') {
              ws.send(JSON.stringify({ event: 'pong' }));
            }
          } catch (e) {
            // Ignorar JSON inválido
          }
        });

        ws.on('close', () => {
          webClients.delete(client);
        });
      } catch (err) {
        ws.close(4002, 'Token inválido o expirado');
      }
      return;
    }

    if (clientType === 'device') {
      if (!deviceId) {
        ws.close(4003, 'deviceId es requerido');
        return;
      }

      const client: DeviceClient = { deviceId, ws, connectedAt: new Date() };
      deviceClients.set(deviceId, client);

      ws.send(JSON.stringify({ event: 'connected', type: 'device', deviceId }));

      // Notificar a clientes web que la cerradura se conectó
      broadcastToWeb('device_status', { deviceId, status: 'ONLINE', timestamp: new Date() });

      ws.on('message', (data) => {
        try {
          const msg = JSON.parse(data.toString());
          if (msg.event === 'heartbeat') {
            ws.send(JSON.stringify({ event: 'heartbeat_ack', timestamp: new Date() }));
          } else if (msg.event === 'card_scanned') {
            // Reenviar escaneo en vivo al frontend
            broadcastToWeb('card_scanned', { deviceId, ...msg.data });
          }
        } catch (e) {
          // Ignorar
        }
      });

      ws.on('close', () => {
        deviceClients.delete(deviceId);
        broadcastToWeb('device_status', { deviceId, status: 'OFFLINE', timestamp: new Date() });
      });
      return;
    }

    // Si no especifica tipo válido
    ws.close(4000, 'Tipo de cliente no especificado (?type=web|device)');
  });

  console.log('[WEBSOCKET] Servidor WebSocket activo en /ws');
  return wss;
}

/**
 * Emite un evento a todos los clientes web (dashboards) conectados
 */
export function broadcastToWeb(event: string, payload: any): void {
  const data = JSON.stringify({ event, payload });
  webClients.forEach((client) => {
    if (client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(data);
    }
  });
}

/**
 * Envía un comando en tiempo real a una cerradura específica (ej: desbloqueo remoto)
 */
export function sendToDevice(deviceId: string, command: any): boolean {
  const client = deviceClients.get(deviceId);
  if (client && client.ws.readyState === WebSocket.OPEN) {
    client.ws.send(JSON.stringify(command));
    return true;
  }
  return false;
}

/**
 * Consulta si una cerradura está conectada por WebSocket
 */
export function isDeviceConnected(deviceId: string): boolean {
  const client = deviceClients.get(deviceId);
  return !!client && client.ws.readyState === WebSocket.OPEN;
}
