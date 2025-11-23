// toke.js - Generador de token para testing
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-in-production';

const payload = {
  userId: 1,
  username: 'admin',
  email: 'admin@ecuatechnology.com',
  roles: ['Administrador']
};

// IMPORTANTE: Incluir issuer y audience igual que en el middleware
const token = jwt.sign(payload, JWT_SECRET, {
  expiresIn: '24h',
  issuer: 'ecuatechnology-api',
  audience: 'ecuatechnology-desktop-app'
});

console.log('========================================');
console.log('Token generado exitosamente:');
console.log('========================================');
console.log(token);
console.log('========================================');
console.log('Copia el token completo de arriba');
console.log('(Todo debe estar en UNA SOLA LÍNEA)');
console.log('========================================');

// Verificar que el token es válido
try {
  const decoded = jwt.verify(token, JWT_SECRET, {
    issuer: 'ecuatechnology-api',
    audience: 'ecuatechnology-desktop-app'
  });
  console.log('\n✅ Token verificado correctamente');
  console.log('Información del token:', JSON.stringify(decoded, null, 2));
} catch (error) {
  console.error('\n❌ Error al verificar el token:', error.message);
}

console.log('\n========================================');
console.log('Configuración actual:');
console.log('JWT_SECRET:', JWT_SECRET ? '✅ Configurado' : '❌ No configurado');
console.log('Expira en: 24 horas');
console.log('========================================');