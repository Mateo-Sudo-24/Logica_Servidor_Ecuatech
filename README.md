```markdown
# README - Backend Sistema Ecuatechnology

![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)
![Express](https://img.shields.io/badge/Express-4.x-blue)
![Prisma](https://img.shields.io/badge/Prisma-5.x-orange)
![License](https://img.shields.io/badge/License-Propietario-red)

## Descripción General

API RESTful completa para el sistema de gestión de servicios técnicos **Ecuatechnology**. Permite manejar órdenes de servicio, clientes, facturación electrónica SRI (Ecuador), portal de clientes, tickets de soporte y aplicación de escritorio para empleados.

### Características Principales
- Autenticación híbrida: JWT (empleados) + Sesiones + OTP (clientes)
- Control de acceso avanzado por roles (RBAC) con jerarquía
- Facturación electrónica completa (PDF + XML SRI)
- Portal web de clientes con aprobación de proformas
- Sistema de tickets de soporte con notificaciones
- Logging estructurado con rotación automática
- Seguridad reforzada (Helmet, rate-limiting, sanitización, prevención de timing attacks)

## Stack Tecnológico

| Capa              | Tecnología                          |
|-------------------|-------------------------------------|
| Runtime           | Node.js 18+                         |
| Framework         | Express.js 4.x                      |
| ORM               | Prisma 5.x                          |
| Autenticación     | JWT + express-session + OTP         |
| Validación        | Zod + validator.js                  |
| Logging           | Winston + Morgan                    |
| PDF               | PDFKit                              |
| Email             | Nodemailer (SMTP / Zimbra)          |
| Proceso           | PM2 (cluster mode)                  |
| Proxy reverso     | Apache 2.4 + mod_proxy              |

## Estructura de Carpetas

```
proyecto/
├── app.js                  # Configuración Express
├── index.js                # Entry point (IIS/Local)
├── auth.js                 # Login JWT empleados
├── config/
│   ├── logger.js
│   └── nodemailer.js
├── src/
│   ├── controllers/        # Lógica de negocio
│   ├── middlewares/        # Seguridad y validación
│   ├── routes/             # Endpoints API
│   └── services/           # Lógica reutilizable
└── start.sh                # PM2 startup
```

## Autenticación Híbrida

| Usuario       | Método         | Aplicación destino       | Duración token/sesión |
|---------------|----------------|--------------------------|-----------------------|
| Empleados     | JWT (Bearer)   | App de escritorio        | 8 horas (refresh 24h) |
| Clientes      | Sesión + OTP   | Portal web               | Hasta logout          |

## Seguridad Implementada

- Helmet + CSP estricto
- HSTS + HTTPS forzoso
- Rate limiting anti-brute force
- Sanitización global de inputs
- Prevención de timing attacks en login
- RBAC con herencia de roles
- Auditoría completa de acciones críticas
- Protección especial del administrador principal

## Endpoints Principales (v1)

```
/api/auth             → Login empleados (JWT)
/api/client-auth      → Registro y login clientes (OTP)
/api/admin            → Gestión de usuarios y roles
/api/employee         → Operaciones por rol (recepción, técnico, ventas)
/api/client           → Portal del cliente
/api/orders           → Gestión de órdenes y facturación
/api/tickets          → Sistema de soporte
/health               → Health check
```

## Despliegue en Producción

### Requisitos
- Node.js 18+
- PM2 + ecosystem.config.js
- Apache 2.4 como proxy reverso (HTTPS + SSL)
- PostgreSQL / MySQL / SQL Server
- Variables de entorno en `.env`

### Comandos rápidos (PM2)

```bash
pm2 start ecosystem.config.js
pm2 reload ecuatechnology-api   # Zero-downtime
pm2 logs ecuatechnology-api
pm2 monit
```

### Despliegue automático (deploy.sh)

```bash
./deploy.sh
# 1. git pull
# 2. npm ci --production
# 3. prisma migrate deploy
# 4. pm2 reload
```

## Variables de Entorno Obligatorias (.env)

```env
NODE_ENV=production
PORT=3000
DATABASE_URL="postgresql://..."
JWT_SECRET=super-secreto-muy-largo
SESSION_SECRET=otro-secreto-largo
SMTP_HOST=smtp.tudominio.com
SMTP_USER=noreply@ecuatechnology.com
SMTP_PASS=******
EMAIL_FROM="Ecuatechnology <noreply@ecuatechnology.com>"
URL_FRONTEND_WEB=https://portal.ecuatechnology.com
URL_FRONTEND_DESK=https://app.ecuatechnology.com
```

## Comandos Útiles

```bash
# Migraciones Prisma
npx prisma migrate deploy
npx prisma generate

# Ver logs de errores
pm2 logs ecuatechnology-api --err

# Health check
curl https://api.ecuatechnology.com/health
```

## Consideraciones Futuras (Roadmap)

- [ ] Migración a microservicios
- [ ] Cola de emails (BullMQ)
- [ ] Firma electrónica SRI automática
- [ ] 2FA obligatorio para administradores
- [ ] Notificaciones push y WhatsApp
- [ ] Containerización (Docker + Kubernetes)
- [ ] OpenAPI/Swagger documentation

## Contacto y Soporte

**Equipo de Desarrollo**  
Email: dev@ecuatechnology.com  
Documentación técnica completa: `DOCUMENTACIÓN_TÉCNICA_BACKEND.pdf`

**Versión actual del backend**: 1.0  
**Última actualización**: Noviembre 2025

---
**¡Gracias por usar Ecuatechnology!**
```
