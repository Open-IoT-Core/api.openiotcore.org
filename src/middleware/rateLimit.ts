import rateLimit from 'express-rate-limit';

/**
 * Rate limiter para rutas críticas de autenticación (Login y Registro)
 * Limita los intentos fallidos y ataques de fuerza bruta.
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 15, // Máximo 15 peticiones por ventana IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Demasiadas tentativas de autenticación desde esta IP. Por favor intente más tarde (15 min).'
  }
});

/**
 * Rate limiter general para la API
 */
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 300, // Máximo 300 peticiones por ventana IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Demasiadas solicitudes desde esta IP, por favor intente más tarde.'
  }
});
