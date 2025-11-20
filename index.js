// index.js - Para IIS con tu app.js real
import dotenv from 'dotenv';
dotenv.config();
import app from './app.js';

console.log('[index.js] ✓ App importada correctamente');
console.log('[index.js] ✓ NODE_ENV:', process.env.NODE_ENV || 'production');

// Detectar si estamos en IIS (process.env.PORT será un named pipe)
const isIIS = process.env.PORT && process.env.PORT.includes('\\\\');

if (isIIS) {
    // En IIS, iisnode maneja el listening automáticamente
    console.log('[index.js] ✓ Modo IIS detectado');
    console.log('[index.js] ✓ Named Pipe:', process.env.PORT);
} else {
    // Desarrollo local - hacer listen normal
    const PORT = process.env.PORT || 3000;
    const HOST = process.env.HOST || '0.0.0.0';
    
    app.listen(PORT, HOST, () => {
        console.log(`[index.js] ✓ Servidor LOCAL escuchando en ${HOST}:${PORT}`);
    });
}

// CRÍTICO: Exportar la app para que run.cjs pueda usarla
export default app;