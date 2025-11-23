Documentación Técnica del Backend - Sistema Ecuatechnology
Índice

Visión General del Sistema
Arquitectura y Estructura
Documentación por Módulos
Sistema de Seguridad
Configuración de Servidor
Consideraciones Futuras


1. Visión General del Sistema
1.1 Descripción General
Sistema de gestión integral para servicios técnicos que maneja órdenes de servicio, clientes, facturación electrónica y tickets de soporte. Implementa autenticación híbrida (JWT para empleados, sesiones para clientes) y control de acceso basado en roles.
1.2 Stack Tecnológico

Runtime: Node.js 18+
Framework: Express.js 4.x
ORM: Prisma 5.x
Autenticación: JWT + Express-Session
Validación: Zod + Validator.js
Logging: Winston + Morgan
Generación PDF: PDFKit
Email: Nodemailer

1.3 Modelo de Autenticación Híbrido
El sistema implementa dos métodos de autenticación simultáneos:

JWT (JSON Web Tokens): Para aplicación de escritorio (empleados)
Session-Based: Para portal web (clientes)


2. Arquitectura y Estructura
2.1 Estructura de Directorios
proyecto/
├── app.js                          # Configuración principal de Express
├── index.js                        # Entry point con manejo IIS/Local
├── auth.js                         # Autenticación JWT (empleados)
├── config/
│   ├── logger.js                   # Configuración Winston
│   └── nodemailer.js               # Sistema de emails
├── src/
│   ├── controllers/                # Lógica de negocio
│   │   ├── adminController.js
│   │   ├── adminTicketsController.js
│   │   ├── clientController.js
│   │   ├── employeeController.js
│   │   └── orderController.js
│   ├── middlewares/                # Middlewares de seguridad
│   │   ├── authMiddleware.js
│   │   ├── httpLogger.js
│   │   ├── jwtAuthMiddleware.js
│   │   ├── roleMiddleware.js
│   │   └── validator.js
│   ├── routes/                     # Definición de endpoints
│   │   ├── adminRoutes.js
│   │   ├── client-auth.js
│   │   ├── clientRoutes.js
│   │   ├── employeeRoutes.js
│   │   ├── orderRoutes.js
│   │   └── ticketRoutes.js
│   └── services/                   # Servicios reutilizables
│       ├── adminService.js
│       ├── employeeService.js
│       └── invoiceService.js
└── start.sh                        # Script de inicio PM2
2.2 Flujo de Peticiones
Cliente HTTP → Rate Limiter → CORS → Body Parser → Sanitización → 
Autenticación Híbrida → Autorización por Roles → Controlador → 
Servicio → Prisma → Base de Datos → Respuesta JSON

3. Documentación por Módulos
3.1 Archivo Principal: app.js
Propósito: Configuración central de la aplicación Express.
Funcionalidades Implementadas:
3.1.1 Seguridad Avanzada con Helmet
javascripthelmet({
  contentSecurityPolicy: { ... },  // Previene XSS
  hsts: { ... }                    // Fuerza HTTPS
})

Content Security Policy para prevenir inyección de scripts
HSTS con preload para forzar conexiones HTTPS
Protección contra clickjacking

3.1.2 CORS Configurado
javascriptcors({
  origin: (origin, callback) => { ... },
  credentials: true
})

Whitelist de orígenes permitidos
Soporte para credenciales (cookies/sessions)
Validación dinámica de origen

3.1.3 Rate Limiting Anti-Brute Force

authLimiter: 5 intentos cada 15 minutos para autenticación
generalLimiter: 100 requests cada 15 minutos para endpoints generales

3.1.4 Manejo Global de Errores
javascriptapp.use((err, req, res, next) => {
  // Log detallado
  // Respuesta sanitizada según entorno
  // No expone stack traces en producción
})
```

**Recomendaciones de Mejora**:
- Implementar rate limiting diferenciado por endpoint sensible
- Agregar compresión de respuestas con `compression` middleware
- Considerar integración con Sentry para monitoreo de errores en producción

---

### 3.2 Autenticación: auth.js

**Propósito**: Sistema de autenticación JWT para empleados.

**Flujo de Autenticación**:
```
Login → Validación Zod → Búsqueda Usuario → Verificación bcrypt → 
Generación JWT → Actualización LastLogin → Respuesta Token
Características de Seguridad:
3.2.1 Prevención de Timing Attacks
javascriptconst dummyHash = '$2b$12$dummyhashtopreventtimingattacks...';
await bcrypt.compare(password, passwordHash || dummyHash);
Siempre ejecuta bcrypt.compare aunque el usuario no exista.
3.2.2 JWT con Metadatos Completos
javascript{
  userId, username, email, roles,
  iat: Math.floor(Date.now() / 1000),
  issuer: 'ecuatechnology-api',
  audience: 'ecuatechnology-desktop-app'
}
3.2.3 Sistema de Refresh Token

Tokens válidos por 8 horas (configurable)
Refresh disponible hasta 24 horas después de emisión
Verificación de usuario activo en cada refresh

Endpoints:

POST /api/auth/login: Autenticación inicial
POST /api/auth/refresh: Renovación de token
POST /api/auth/verify: Validación de token
POST /api/auth/logout: Cierre de sesión (registro auditoría)

Recomendaciones:

Implementar token blacklist para logout forzado
Considerar refresh token rotation
Agregar 2FA para roles administrativos


3.3 Sistema de Logging: config/logger.js
Propósito: Logging estructurado con rotación automática.
Niveles de Log:
javascript{ error: 0, warn: 1, info: 2, http: 3, debug: 4 }
```

**Transports Configurados**:
- **Console**: Colorizado para desarrollo
- **DailyRotateFile Combined**: Todos los logs, retención 14 días
- **DailyRotateFile Error**: Solo errores, retención 30 días

**Formato Estandarizado**:
```
[2024-01-15 10:30:45] INFO: Login exitoso - Usuario: admin
Recomendaciones:

Integrar con servicio externo (Datadog, CloudWatch)
Implementar log aggregation para análisis
Agregar alertas automáticas para errores críticos


3.4 Sistema de Emails: config/nodemailer.js
Propósito: Envío de emails transaccionales con plantillas HTML.
Configuración Dual:

Soporte SMTP genérico
Soporte Zimbra específico

Plantillas Disponibles:
3.4.1 Emails Operativos

sendMailToReceptionist: Credenciales iniciales
sendOTPEmail: Código de verificación 2FA
sendPasswordChangedByAdmin: Notificación cambio contraseña
sendForgotPasswordRequest: Solicitud recuperación

3.4.2 Emails de Negocio

sendProformaEmail: Envío de cotización
sendProformaConfirmationEmail: Confirmación aprobación/rechazo

3.4.3 Emails de Clientes

sendVerificationEmail: Verificación email registro
sendPasswordResetEmail: Recuperación contraseña cliente

3.4.4 Emails de Soporte

sendTicketUpdateEmail: Actualización estado ticket
sendTicketAssignmentEmail: Asignación ticket a staff
sendNewTicketMessageEmail: Nuevo mensaje en ticket

Características de Diseño:

Responsive (compatible mobile)
Colores corporativos configurables
Botones de acción directa
Información estructurada en tablas

Mapa de Estados para Tickets:
javascriptSTATUS_MAP = {
  'open': { label: 'Abierto', description: '...' },
  'assigned': { label: 'Asignado', description: '...' },
  'in_progress': { label: 'En Progreso', description: '...' },
  'resolved': { label: 'Resuelto', description: '...' },
  'closed': { label: 'Cerrado', description: '...' }
}
Recomendaciones:

Implementar cola de emails (Bull/BullMQ)
Agregar retry logic para fallos de envío
Almacenar historial de emails enviados
Implementar unsubscribe para emails promocionales


3.5 Entry Point: index.js
Propósito: Punto de entrada con soporte IIS/Local.
Detección de Entorno:
javascriptconst isIIS = process.env.PORT && process.env.PORT.includes('\\\\');
Modos de Ejecución:

IIS Mode: iisnode maneja el listening automáticamente
Local Mode: Express listen en HOST:PORT configurado

Recomendaciones:

Agregar graceful shutdown
Implementar health checks para load balancers
Considerar cluster mode para aprovechar múltiples CPUs


3.6 Controladores
3.6.1 adminController.js
Propósito: Gestión completa del sistema (usuarios, roles, logs).
Módulos Principales:
A) Gestión de Usuarios

adminCreateUser: Creación con validación de roles
adminUpdateUser: Actualización de información
adminDeleteUser: Eliminación con protecciones
adminListUsers: Listado con información de roles
adminSetUserPassword: Cambio de contraseña por admin

Protecciones Implementadas:
javascript// No eliminar admin principal
if (userIdNum === PROTECTED_USER_ID) throw Error(...);

// No auto-eliminarse
if (userIdNum === req.auth.userId) throw Error(...);

// Solo admin puede eliminar admin
if (isDeletingAdmin && !isAdmin(req.auth.roles)) throw Error(...);
B) Gestión de Roles

adminCreateRole: Creación de roles personalizados
adminListRoles: Listado con conteo de usuarios
adminUpdateRole: Actualización de rol
adminDeleteRole: Eliminación con advertencia de usuarios afectados
adminAssignRole: Asignación/remoción de rol a usuario

Validación de Asignación:
javascript// Protección: No remover propio rol admin
if (action === 'remove' && 
    roleName === 'Administrador' && 
    userId === req.auth.userId) throw Error(...);
C) Sistema y Monitoreo

getSystemLogs: Lectura de logs con filtros (nivel, fecha)
getSystemStatistics: Métricas del sistema

Estructura de Log Entry:
javascript{
  action: 'USER_CREATED',
  performedBy: { userId, username, roles },
  target: { userId, username },
  details: { ... },
  timestamp: ISO 8601,
  ip: IP Address
}
Recomendaciones:

Implementar soft delete para usuarios
Agregar campo de razón para eliminaciones
Implementar exportación de logs a CSV/JSON
Crear dashboard de estadísticas en tiempo real


3.6.2 adminTicketsController.js
Propósito: Gestión administrativa de tickets de soporte.
Funcionalidades:
A) Consulta y Visualización

listAllTickets: Listado con filtros múltiples
getTicketDetails: Información completa con historial

Filtros Disponibles:
javascript{ status, priority, assignedTo, category, clientId, orderId }
B) Gestión de Tickets

assignTicket: Asignación a usuario con registro automático
updateTicketStatus: Cambio de estado con notificación
addTicketResponse: Agregar respuesta (interna/pública)

Estados de Ticket:
javascriptTICKET_STATUS = {
  OPEN: 'open',
  ASSIGNED: 'assigned',
  IN_PROGRESS: 'in_progress',
  RESOLVED: 'resolved',
  CLOSED: 'closed'
}
```

**C) Operaciones Especiales**
- `modifyOrderFromTicket`: Modificación de orden desde ticket (solo admin)
- `bulkCloseTickets`: Cierre masivo de tickets
- `getTicketStatistics`: Estadísticas y métricas

**Flujo de Modificación de Orden**:
```
Verificar ticket → Verificar orden relacionada → 
Modificar orden → Registrar historial → 
Crear respuesta ticket → Resolver ticket
Estadísticas Generadas:

Total de tickets por estado
Total de tickets por prioridad
Total de tickets por categoría
Tiempo promedio de resolución

Recomendaciones:

Implementar SLA (Service Level Agreement) tracking
Agregar sistema de escalamiento automático
Crear templates de respuesta
Implementar chatbot para respuestas iniciales


3.6.3 clientController.js
Propósito: Portal del cliente con gestión de órdenes y tickets.
Módulos Principales:
A) Autenticación con OTP
javascriptrequestOTP → generateOTP() → Almacenar BD → 
Enviar Email → clientLoginWithOTP → Validar → 
Crear Sesión → Limpiar OTP
Configuración OTP:

Código de 6 dígitos
Validez de 10 minutos
Un solo uso
Timing attack prevention

B) Gestión de Órdenes

getOrderStatusWithHistory: Consulta pública con historial completo
listMyOrdersWithHistory: Órdenes del cliente con timeline
viewOrderDetails: Detalles específicos con verificación de propiedad

Respuesta Estructurada de Orden:
javascript{
  orderId, identityTag,
  currentStatus, statusHistory: [ ... ],
  diagnosis, totalPrice, parts,
  intakeDate, estimatedDeliveryDate,
  serviceStartDate, serviceEndDate,
  proformaStatus, proformaSentDate,
  equipment: { ... },
  receptionist, technician,
  equipmentEntry: { ... },
  equipmentExit: { ... }
}
```

**C) Sistema de Proformas**
- `approveOrRejectProforma`: Aprobación/rechazo con actualización de estado

**Flujo de Aprobación**:
```
Validar autenticación → Verificar ownership → 
Validar estado proforma → Actualizar orden → 
Cambiar estado sistema → Registrar historial → 
Enviar confirmación email
D) Sistema de Tickets

createSupportTicket: Creación con categorización
listMyTickets: Listado con filtros
viewTicketDetails: Detalles con mensajes

Categorías de Ticket:

Modificación de orden
Consulta técnica
Problema con servicio
Solicitud de información

E) Gestión de Perfil

registerClient: Registro con validación
getClientProfile: Información del cliente
updateClientProfile: Actualización de datos
verifyEmail: Verificación de email
requestPasswordReset: Recuperación de contraseña
resetPassword: Restablecimiento con token

Validaciones de Registro:
javascript- Email único
- IdNumber único (si se proporciona)
- ClientType válido
- Servicios públicos requieren organizationName
```

**F) Sistema de Notificaciones**
- `getClientNotifications`: Notificaciones pendientes
- `markNotificationAsRead`: Marcar como leída

**Recomendaciones**:
- Implementar notificaciones push
- Agregar sistema de favoritos/órdenes recurrentes
- Crear sistema de valoración de servicio
- Implementar chat en vivo con soporte

---

#### 3.6.4 employeeController.js

**Propósito**: Operaciones de empleados según rol (Recepcionista, Técnico, Ventas).

**Módulos por Rol**:

**A) Recepcionista**

**Funciones Principales**:
- `searchClients`: Búsqueda con filtros múltiples
- `listTechnicians`: Técnicos disponibles para asignación
- `listClientEquipments`: Equipos de cliente específico
- `receptionistCreateOrUpdateClient`: Gestión de clientes
- `receptionistRegisterEquipment`: Registro de equipos
- `receptionistCreateOrder`: Creación de orden con entrada automática
- `receptionistRegisterEquipmentExit`: Salida y entrega

**Flujo de Creación de Orden**:
```
Validar cliente → Validar equipo → Obtener estado RECIBIDO → 
Crear orden en transacción → Registrar entrada equipo → 
Registrar historial → Asignar técnico (opcional)
B) Staff Técnico
Funciones Principales:

techListAssignedOrders: Órdenes asignadas al técnico
techSetDiagnosis: Establecer diagnóstico
techStartService: Iniciar servicio (marca fecha inicio)
techEndService: Finalizar servicio (marca fecha fin)
techDashboard: Métricas de rendimiento

Estados Manejados:
javascriptRECIBIDO → DIAGNOSTICADO → EN_PROGRESO → COMPLETADO
Métricas del Dashboard:
javascript{
  assignedOrders,              // Total asignadas
  ordersInProgress,            // En progreso
  completedToday,              // Completadas hoy
  completedThisWeek,           // Completadas semana
  avgRepairTime,               // Tiempo promedio (horas)
  pendingDiagnosis             // Pendientes diagnóstico
}
```

**C) Staff Ventas**

**Funciones Principales**:
- `salesListOrders`: Listado con filtros avanzados
- `salesAddPartsAndPrice`: Generar proforma
- `salesSendProforma`: Enviar proforma por email

**Flujo de Proforma**:
```
Agregar Parts y TotalPrice → Estado: generada → 
Enviar Email → Estado: enviada → 
Cliente Aprueba → Estado: aprobada → 
Técnico puede proceder
Validaciones de Envío:
javascript// Orden debe existir
if (!order) throw Error('Orden no encontrada');

// Cliente debe tener email
if (!order.client?.Email) throw Error('Cliente sin email');

// Proforma debe estar generada
if (order.ProformaStatus !== 'generada') throw Error('Estado incorrecto');
D) Autenticación de Empleados

employeeLogin: Login con sesión
employeeChangePassword: Cambio de contraseña
employeeForgotPassword: Solicitud a admin IT
employeeLogout: Cierre de sesión

Recomendaciones:

Implementar sistema de notificaciones en tiempo real
Agregar firma digital para órdenes completadas
Crear sistema de calificación interna de técnicos
Implementar programación de citas para recepciones


3.6.5 orderController.js
Propósito: Gestión de órdenes y facturación electrónica.
Módulos Principales:
A) Consulta de Órdenes

getAllOrders: Listado completo con paginación
getOrdersByClient: Órdenes del cliente autenticado
getOrderById: Orden específica con verificación de acceso
getOrderTracking: Timeline visual de estados

Control de Acceso:
javascriptcanAccessOrder(order, req) {
  // Empleados: todas las órdenes
  if (req.auth.type === 'employee') return true;
  
  // Clientes: solo sus órdenes
  if (req.auth.type === 'client' && 
      order.ClientId === req.auth.clientId) return true;
  
  return false;
}
```

**B) Sistema de Facturación Electrónica**

**Funciones Principales**:
- `generateOrderInvoice`: Generar factura PDF + XML
- `sendInvoiceToClient`: Envío por correo
- `downloadInvoicePDF`: Descarga PDF
- `downloadInvoiceXML`: Descarga XML (SRI Ecuador)
- `listInvoices`: Listado de facturas

**Flujo de Generación de Factura**:
```
Validar orden completada → Validar proforma aprobada → 
Generar número secuencial → Generar PDF → Generar XML SRI → 
Guardar archivos → Crear registro BD → 
Actualizar estado orden → Registrar historial
Validaciones Pre-Facturación:
javascript// Orden debe estar completada
if (order.status.Code !== 'COMPLETADO') throw Error(...);

// Proforma debe estar aprobada
if (order.ProformaStatus !== 'aprobada') throw Error(...);

// No duplicar factura
if (order.invoice) throw Error('Ya tiene factura');
Generación de Número de Factura:
javascript// Formato: 001-001-000000001
const lastInvoice = await prisma.invoice.findFirst({
  orderBy: { InvoiceNumber: 'desc' }
});

const sequence = parseInt(lastParts[2]) + 1;
const invoiceNumber = `001-001-${sequence.padStart(9, '0')}`;
Estructura de Factura en BD:
javascript{
  InvoiceNumber,           // 001-001-000000001
  IssueDate,              // Fecha emisión
  TotalAmount,            // Monto total
  SubTotal,               // Sin IVA
  Tax,                    // IVA 12%
  Status,                 // generated/sent/approved
  PDFPath,                // /storage/invoices/pdf/...
  XMLPath,                // /storage/invoices/xml/...
  IssuedByUserId,         // Usuario que generó
  SentDate                // Fecha de envío
}
Recomendaciones:

Implementar firma electrónica para XML
Integrar con autorización SRI en tiempo real
Agregar sistema de factura rectificativa
Implementar reconciliación automática de pagos
Crear reportes de facturación mensual


3.7 Middlewares de Seguridad
3.7.1 authMiddleware.js
Propósito: Autenticación híbrida unificada.
Estrategias de Autenticación:
A) JWT (Empleados)
javascriptAuthorization: Bearer <token>
Validaciones JWT:

Token no expirado
Issuer y Audience correctos
Usuario existe en BD
Usuario activo

B) Session (Clientes)
javascriptCookie: sessionId=<encrypted-session-id>
Validaciones Session:

Sesión válida y no expirada
clientId existe en BD
Cliente activo

Objeto req.auth Unificado:
javascript// Empleado
{
  userId, username, email, roles,
  type: 'employee',
  authMethod: 'jwt'
}

// Cliente
{
  clientId, displayName, email,
  roles: ['Cliente'],
  type: 'client',
  authMethod: 'session'
}
Middlewares Especializados:

requireClientAuth(): Solo clientes
requireEmployeeAuth(): Solo empleados
requireRoles(allowedRoles): Roles específicos
requireOwnership(paramName, userIdField): Verificar propiedad

Manejo de Errores:
javascript// Token expirado
{ error: 'Token expirado', code: 'TOKEN_EXPIRED', expiredAt: ... }

// Token inválido
{ error: 'Token inválido', code: 'TOKEN_INVALID' }

// Usuario inactivo
{ error: 'Usuario inactivo', code: 'USER_INACTIVE' }

// Sesión inválida
{ error: 'Sesión inválida', code: 'SESSION_INVALID' }
Recomendaciones:

Implementar refresh token automático antes de expiración
Agregar geolocalización para detección de accesos anómalos
Implementar límite de sesiones concurrentes
Crear sistema de notificación de nuevos logins


3.7.2 roleMiddleware.js
Propósito: Control de acceso basado en roles (RBAC).
Constantes del Sistema:
javascriptSYSTEM_ROLES = {
  ADMIN: 'Administrador',
  RECEPTIONIST: 'Recepcionista',
  TECHNICIAN: 'Staff Técnico',
  SALES: 'Staff Ventas',
  CLIENT: 'Cliente'
}

USER_TYPES = {
  EMPLOYEE: 'employee',
  CLIENT: 'client',
  ANY: 'any'
}
Jerarquía de Roles:
javascriptROLE_HIERARCHY = {
  'Administrador': ['Administrador', 'Recepcionista', 'Staff Técnico', 'Staff Ventas'],
  'Recepcionista': ['Recepcionista'],
  'Staff Técnico': ['Staff Técnico'],
  'Staff Ventas': ['Staff Ventas'],
  'Cliente': ['Cliente']
}
El administrador hereda todos los permisos.
Middleware Principal: requireAccess(options)
Opciones:
javascript{
  allowedRoles: [],           // Roles permitidos
  userType: 'any',            // employee/client/any
  strictValidation: false,    // Requiere roles específicos
  useHierarchy: true          // Usar herencia de roles
}
```

**Proceso de Validación**:
```
1. Verificar autenticación (req.auth existe)
2. Validar estructura de auth
3. Verificar tipo de usuario requerido
4. Normalizar roles del usuario
5. Expandir roles con jerarquía (si habilitado)
6. Verificar coincidencia de roles
7. Registrar acceso exitoso o denegado
Middlewares Especializados:
javascriptrequireEmployeeRoles([roles])    // Empleados con roles específicos
requireEmployeeAuth()            // Cualquier empleado
requireClientAuth()              // Solo clientes
requireAnyAuth()                 // Cualquier usuario autenticado
requireAdmin()                   // Solo administrador
requireReception()               // Admin o Recepcionista
requireTechnical()               // Admin o Staff Técnico
requireSales()                   // Admin o Staff Ventas
Middleware Híbrido:
javascriptrequireHybridRoles(employeeRoles, allowClients)
// Permite empleados con roles específicos O clientes
Middleware de Propiedad de Recurso:
javascriptrequireResourceOwnership(resourceIdParam, ownerField)
// Clientes solo acceden a sus recursos
// Empleados acceden a cualquier recurso
Códigos de Error:
javascriptROLE_ERROR_CODES = {
  MISSING_AUTH: 'ROLE_001',
  INVALID_USER_TYPE: 'ROLE_002',
  MISSING_ROLES: 'ROLE_003',
  INSUFFICIENT_PERMISSIONS: 'ROLE_004',
  // ... más códigos
}
Logging de Auditoría:
javascriptlogger.info('Verificación de acceso exitosa', {
  requestId, userId, username, userType, roles,
  path, processingTime
});

logger.warn('Acceso denegado por permisos insuficientes', {
  requestId, userId, userRoles, requiredRoles,
  path, method, processingTime
});
Recomendaciones:

Implementar permisos granulares por endpoint
Crear sistema de permisos temporales
Agregar auditoría de cambios de roles
Implementar delegación de permisos


3.7.3 validator.js
Propósito: Validación y sanitización de datos con Zod y Validator.js.
Funciones de Validación Personalizada:
A) Email
javascriptvalidateAndSanitizeEmail(email) {
  return {
    isValid: validator.isEmail(trimmed),
    sanitized: validator.normalizeEmail(trimmed)
  }
}
B) Contraseña Fuerte
javascriptvalidateStrongPassword(password) {
  // Mínimo 8 caracteres
  // 1 mayúscula, 1 minúscula, 1 número
  return validator.isStrongPassword(password, { ... });
}
C) Texto Sanitizado
javascriptsanitizeText(input) {
  return validator.escape(input.trim());
}
D) Teléfono
javascriptvalidatePhone(phone) {
  return validator.isMobilePhone(phone, 'any', { strictMode: false });
}
E) Cédula Ecuatoriana
javascriptvalidateEcuadorianId(idNumber) {
  // Validación con algoritmo de verificación
  // Provincia entre 1-24
  // Cálculo de dígito verificador
}
Refinamientos Zod:
javascriptemailRefinement = z.string()
  .min(1)
  .refine(isValid)
  .transform(sanitize);

strongPasswordRefinement = z.string()ReintentarMContinuar.min(8)
.refine(validateStrongPassword);
sanitizedString = (minLength, maxLength) =>
z.string()
.min(minLength)
.max(maxLength)
.transform(sanitizeText);

**Middleware de Validación**:
```javascript
validate(schema, source = 'body') {
  return (req, res, next) => {
    try {
      const parsed = schema.parse(req[source]);
      req[source] = parsed;
      next();
    } catch (error) {
      res.status(400).json({
        success: false,
        error: 'Datos inválidos',
        details: error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message,
          code: err.code
        }))
      });
    }
  }
}
```

**Schemas Definidos**:

**Autenticación**:
- `login`: workId, password
- `changePassword`: oldPassword, newPassword
- `forgotPassword`: workId

**Clientes**:
- `createClient`: Todos los campos con validaciones
- `updateClient`: Campos actualizables

**Equipos**:
- `registerEquipment`: clientId, equipmentTypeId, marca, modelo

**Órdenes**:
- `createOrder`: clientId, equipmentId, notas, fecha entrega
- `registerEquipmentExit`: orderId, nombre receptor

**Técnicos**:
- `setDiagnosis`: orderId, diagnosis (mínimo 10 caracteres)
- `startService`: orderId
- `endService`: orderId, finalNotes

**Ventas**:
- `generateProforma`: orderId, parts, totalPrice
- `sendProforma`: orderId

**Middleware de Sanitización Global**:
```javascript
sanitizeRequest(req, res, next) {
  // Sanitiza recursivamente:
  // - req.body
  // - req.query
  // - req.params
}
```

**Funciones Auxiliares**:
```javascript
validateData(schema, data) {
  // Validación fuera de middleware
  return { success, data, errors };
}

sanitizeObject(obj) {
  // Sanitización recursiva de objetos
}
```

**Recomendaciones**:
- Agregar validación de archivos subidos
- Implementar rate limiting por validaciones fallidas
- Crear schemas reutilizables para tipos comunes
- Agregar validación de formato de fecha ISO 8601

---

#### 3.7.4 httpLogger.js

**Propósito**: Logging de peticiones HTTP con Morgan y Winston.

**Tokens Personalizados**:
```javascript
morgan.token('user-id', (req) => {
  if (req.auth?.userId) return `User:${req.auth.userId}`;
  if (req.auth?.clientId) return `Client:${req.auth.clientId}`;
  return 'Anonymous';
});

morgan.token('auth-type', (req) => {
  if (req.auth?.authMethod) return req.auth.authMethod.toUpperCase();
  if (req.headers.authorization?.startsWith('Bearer')) return 'JWT';
  if (req.session?.userId) return 'SESSION';
  return 'NONE';
});

morgan.token('user-roles', (req) => {
  return req.auth?.roles?.join(',') || 'N/A';
});
```

**Formatos de Log**:

**Desarrollo**:
[:date] :method :url :status :response-time ms - :res bytes |
:user-id (:auth-type) | Roles: :user-roles

**Producción**:
:remote-addr - :user-id [:date] ":method :url HTTP/:http-version" :status
:res ":referrer" ":user-agent" :response-time ms

**Middlewares Adicionales**:

**A) Error Logger**
```javascript
httpErrorLogger(err, req, res, next) {
  if (res.statusCode >= 400) {
    logger.error('HTTP Error', {
      method, url, statusCode, errorMessage,
      errorStack: (dev ? stack : undefined),
      userId, authType, ip, userAgent,
      body: (dev ? req.body : undefined)
    });
  }
}
```

**B) Slow Request Logger**
```javascript
slowRequestLogger(threshold = 1000) {
  // Detecta peticiones que tardan más del threshold
  logger.warn('Slow Request Detected', {
    method, url, duration, statusCode, userId
  });
}
```

**C) Audit Logger**
```javascript
auditLogger(req, res, next) {
  // Loguea operaciones críticas (POST, PUT, DELETE)
  logger.info('Audit Log', {
    action: req.method,
    endpoint: req.url,
    userId, userType, roles,
    affectedResource
  });
}
```

**Función Skip**:
```javascript
skip(req, res) {
  // En producción omitir:
  // - Health checks
  // - Assets estáticos
  // - Peticiones exitosas simples (opcional)
}
```

**Recomendaciones**:
- Implementar log streaming a servicio externo
- Agregar correlación de requests (request-id)
- Crear alertas para patrones anómalos
- Implementar análisis de rendimiento automático

---

### 3.8 Rutas (Routes)

#### 3.8.1 adminRoutes.js

**Propósito**: Endpoints de administración del sistema.

**Gestión de Usuarios**:
POST   /api/admin/user/create          - Crear usuario
PUT    /api/admin/user/update          - Actualizar usuario
DELETE /api/admin/user/delete          - Eliminar usuario
GET    /api/admin/user/list            - Listar usuarios
POST   /api/admin/user/set-password    - Cambiar contraseña
POST   /api/admin/user/assign-role     - Asignar/remover rol

**Gestión de Roles**:
POST   /api/admin/role/create          - Crear rol
GET    /api/admin/role/list            - Listar roles
PUT    /api/admin/role/update          - Actualizar rol
DELETE /api/admin/role/delete          - Eliminar rol

**Sistema y Monitoreo**:
GET    /api/admin/system/logs          - Ver logs
GET    /api/admin/system/statistics    - Estadísticas
GET    /api/admin/system/health        - Estado del sistema
GET    /api/admin/dashboard            - Dashboard admin
GET    /api/admin/audit/actions        - Logs de auditoría

**Permisos Requeridos**:
- Mayoría de endpoints: Solo Administrador
- Logs del sistema: Administrador o Staff Técnico
- Salud del sistema: Administrador o Staff Técnico

---

#### 3.8.2 client-auth.js

**Propósito**: Autenticación de clientes con OTP.

**Endpoints de Autenticación**:
POST /api/client-auth/register-web       - Registro de cliente
POST /api/client-auth/request-otp        - Solicitar OTP
POST /api/client-auth/login-otp          - Login con OTP
POST /api/client-auth/login              - Login tradicional (legacy)
POST /api/client-auth/logout             - Cerrar sesión
GET  /api/client-auth/verify             - Verificar sesión

**Flujo de Login con OTP**:

Cliente ingresa email
Sistema genera OTP de 6 dígitos
Se guarda en BD con expiración 10 minutos
Se envía por email
Cliente ingresa OTP
Sistema valida y crea sesión
OTP se marca como usado


**Rate Limiting**:
- OTP Request: 3 intentos / 15 minutos
- Login: 5 intentos / 15 minutos

**Registro de Cliente**:
```javascript
Validaciones:
- DisplayName, Email, Password requeridos
- Email único
- Password hasheado con bcrypt (10 rounds)
- ClientTypeId = 1 (debe existir en BD)
```

**Recomendaciones**:
- Implementar OTP por SMS como alternativa
- Agregar verificación de email obligatoria
- Implementar lista de emails bloqueados
- Crear sistema de recuperación de cuenta

---

#### 3.8.3 clientRoutes.js

**Propósito**: Portal completo del cliente.

**Rutas Públicas** (sin autenticación):
GET  /api/client/order-status            - Consulta pública
POST /api/client/auth/register           - Registro
POST /api/client/auth/request-otp        - Solicitar OTP
POST /api/client/auth/login-otp          - Login OTP
POST /api/client/auth/login              - Login tradicional
POST /api/client/auth/verify-email       - Verificar email
POST /api/client/auth/resend-verification - Reenviar verificación
POST /api/client/auth/forgot-password    - Recuperación
POST /api/client/auth/reset-password     - Restablecer

**Rutas Protegidas** (requieren autenticación):

**Autenticación**:
POST /api/client/auth/change-password    - Cambiar contraseña
POST /api/client/auth/logout             - Cerrar sesión

**Perfil**:
GET  /api/client/profile                 - Ver perfil
PUT  /api/client/profile                 - Actualizar perfil

**Órdenes**:
GET  /api/client/my-orders               - Mis órdenes
GET  /api/client/orders/:orderId         - Detalle de orden
POST /api/client/orders/notify-creation  - Notificar creación

**Proformas**:
POST /api/client/proforma/respond        - Aprobar/rechazar

**Tickets**:
POST /api/client/tickets/create          - Crear ticket
GET  /api/client/tickets/my-tickets      - Mis tickets
GET  /api/client/tickets/:ticketId       - Detalle ticket

**Notificaciones**:
GET  /api/client/notifications           - Ver notificaciones
POST /api/client/notifications/mark-read - Marcar leída

**Endpoints Legacy**:
GET  /api/client/status                  - Estado orden (legacy)
GET  /api/client/orders                  - Órdenes (legacy)

---

#### 3.8.4 employeeRoutes.js

**Propósito**: Operaciones de empleados por rol.

**Rutas Públicas**:
POST /api/employee/login                 - Login
POST /api/employee/forgot-password       - Recuperación

**Rutas Generales** (cualquier empleado):
POST /api/employee/change-password       - Cambiar contraseña
POST /api/employee/logout                - Cerrar sesión
GET  /api/employee/notifications         - Notificaciones
GET  /api/employee/search/orders         - Buscar órdenes
GET  /api/employee/technicians           - Listar técnicos
GET  /api/employee/search/clients        - Buscar clientes
GET  /api/employee/client/:id/equipments - Equipos cliente
GET  /api/employee/equipment-types       - Tipos equipo
GET  /api/employee/client-types          - Tipos cliente
GET  /api/employee/statuses              - Estados sistema
GET  /api/employee/orders/:orderId       - Detalle orden

**Recepcionista** (Admin o Recepcionista):
POST /api/employee/receptionist/client           - Crear/actualizar cliente
POST /api/employee/receptionist/equipment        - Registrar equipo
POST /api/employee/receptionist/create-order     - Crear orden
POST /api/employee/receptionist/equipment-exit   - Registrar salida
GET  /api/employee/receptionist/dashboard        - Dashboard

**Staff Técnico** (Admin o Staff Técnico):
GET  /api/employee/tech/orders                   - Órdenes asignadas
POST /api/employee/tech/diagnosis                - Diagnóstico
POST /api/employee/tech/start-service            - Iniciar servicio
POST /api/employee/tech/end-service              - Finalizar servicio
GET  /api/employee/technical/dashboard           - Dashboard técnico

**Staff Ventas** (Admin o Staff Ventas):
GET  /api/employee/sales/orders                  - Órdenes
POST /api/employee/sales/parts-price             - Generar proforma
POST /api/employee/sales/send-proforma           - Enviar proforma
GET  /api/employee/sales/reports                 - Reportes
GET  /api/employee/sales/dashboard               - Dashboard ventas

**Administrador** (Solo Admin):
GET  /api/employee/admin/statistics              - Estadísticas
GET  /api/employee/admin/reception-staff         - Personal recepción
GET  /api/employee/admin/technical-staff         - Personal técnico
GET  /api/employee/admin/sales-staff             - Personal ventas
GET  /api/employee/admin/audit/status-changes    - Auditoría
GET  /api/employee/admin/users                   - Gestión usuarios

---

#### 3.8.5 orderRoutes.js

**Propósito**: Gestión de órdenes y facturación.

**Rutas de Consulta**:
GET /api/orders/my-orders              - Cliente: sus órdenes
GET /api/orders/:id                    - Detalle orden (híbrido)
GET /api/orders/:id/tracking           - Timeline (híbrido)
GET /api/orders/admin/all-orders       - Admin: todas las órdenes
GET /api/orders/admin/invoices         - Admin/Ventas: facturas

**Facturación Electrónica**:
POST /api/orders/:id/admin/generate-invoice  - Generar factura
POST /api/orders/:id/admin/send-invoice      - Enviar factura
GET  /api/orders/:id/download-invoice        - Descargar PDF
GET  /api/orders/:id/download-invoice-xml    - Descargar XML

**Control de Acceso**:
- Clientes: Solo sus órdenes
- Empleados: Todas las órdenes según rol
- Facturación: Solo Admin y Staff Ventas

---

#### 3.8.6 ticketRoutes.js

**Propósito**: Sistema de tickets de soporte.

**Rutas de Clientes**:
POST /api/tickets/create               - Crear ticket
GET  /api/tickets/my-tickets           - Mis tickets
GET  /api/tickets/:ticketId            - Detalle ticket

**Rutas de Staff**:
GET  /api/tickets/admin/list           - Todos los tickets
GET  /api/tickets/admin/:ticketId      - Detalle completo
POST /api/tickets/admin/assign         - Asignar ticket
PUT  /api/tickets/admin/status         - Actualizar estado
POST /api/tickets/admin/response       - Agregar respuesta
PUT  /api/tickets/admin/modify-order   - Modificar orden
POST /api/tickets/admin/bulk-close     - Cierre masivo
GET  /api/tickets/admin/statistics     - Estadísticas

**Rutas Generales**:
GET  /api/tickets/categories           - Categorías disponibles

---

### 3.9 Servicios (Services)

#### 3.9.1 adminService.js

**Propósito**: Lógica reutilizable de administración.

**Funciones de Roles**:
```javascript
createRole(name, description)
listRoles()
updateRole(roleId, name, description)
deleteRole(roleId)  // Solo si no está asignado
```

**Funciones de Usuarios**:
```javascript
createUserWithRole({ email, username, password, roleName, sendEmail })
adminChangePassword(userId, newPassword, notifyEmail)
findUserByUsernameOrEmail(identifier)
```

**Flujo de Creación de Usuario**:
Hash contraseña → Crear usuario →
Asignar rol → Enviar email (si habilitado) →
Retornar usuario con roles

---

#### 3.9.2 employeeService.js

**Propósito**: Operaciones comunes de empleados.

**Funciones OTP**:
```javascript
generateAndSendOTP(userId, email)
// - Genera 6 dígitos
// - Guarda en tabla OTP
// - Expira en 10 minutos
// - Envía por email

verifyOTP(userId, otpCode)
// - Verifica código
// - Verifica no expirado
// - Marca como usado
```

**Funciones de Cliente**:
```javascript
createOrUpdateClient(clientData, isNew)
// - Valida IdNumber único (nuevo)
// - Crea o actualiza cliente
```

**Funciones de Equipo**:
```javascript
registerEquipment(equipmentData)
// - Registra equipo para cliente
```

**Funciones de Proforma**:
```javascript
sendProformaToClient(orderId, clientEmail, clientName, identityTag, parts, totalPrice)
// - Valida email
// - Envía proforma por email
// - Registra envío

sendProformaClientConfirmation(clientEmail, clientName, identityTag, action)
// - Envía confirmación aprobación/rechazo
```

---

#### 3.9.3 invoiceService.js

**Propósito**: Generación de facturas electrónicas.

**Funciones Principales**:

**A) generateInvoicePDF(order, invoiceNumber)**

Genera PDF profesional con:
- Encabezado corporativo
- Información del cliente
- Detalles del equipo
- Descripción del servicio
- Tabla de costos (subtotal, IVA, total)
- Pie de página con información legal

Retorna: `{ buffer, filename }`

**B) generateElectronicInvoiceXML(order, invoiceNumber)**

Genera XML según estándares SRI Ecuador:
- Información tributaria
- Clave de acceso (algoritmo módulo 11)
- Información de la factura
- Detalles de productos/servicios
- Impuestos (IVA 0% y 12%)
- Información adicional

Estructura XML:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<factura id="comprobante" version="1.0.0">
  <infoTributaria>...</infoTributaria>
  <infoFactura>...</infoFactura>
  <detalles>...</detalles>
  <infoAdicional>...</infoAdicional>
</factura>
```

**C) sendInvoiceEmail(clientEmail, clientName, invoiceNumber, pdfBuffer, xmlBuffer)**

Envía factura por correo electrónico con adjuntos PDF y XML.

**D) sendInvoiceToExternalApp(pdfBuffer, meta)**

Integración con aplicación externa (opcional).

**Funciones Auxiliares**:
```javascript
generarClaveAccesoCompleta(invoiceNumber)
// Genera clave de 48 dígitos según SRI

calcularDigitoVerificador(claveBase)
// Algoritmo módulo 11 del SRI

identificarTipoDocumento(idType, idNumber)
// 04: RUC, 05: Cédula, 06: Pasaporte, 07: Consumidor final
```

**Recomendaciones**:
- Implementar firma digital PKCS#12
- Integrar autorización automática con SRI
- Agregar generación de RIDE (representación impresa)
- Implementar retry logic para autorización fallida

---

## 4. Sistema de Seguridad

### 4.1 Capas de Seguridad Implementadas

#### 4.1.1 Nivel de Red
- **CORS**: Whitelist de orígenes configurada
- **Helmet**: Headers de seguridad (CSP, HSTS, X-Frame-Options)
- **Rate Limiting**: Protección contra brute force y DDoS

#### 4.1.2 Nivel de Autenticación
- **JWT**: Tokens firmados con HS256
- **Sessions**: Cookies httpOnly, secure en producción
- **OTP**: Códigos de un solo uso con expiración
- **Bcrypt**: Hash de contraseñas con 12 rounds

#### 4.1.3 Nivel de Autorización
- **RBAC**: Control basado en roles
- **Jerarquía de Roles**: Admin hereda todos los permisos
- **Verificación de Propiedad**: Clientes solo acceden a sus recursos

#### 4.1.4 Nivel de Datos
- **Sanitización**: Escape de HTML con validator.js
- **Validación**: Schemas Zod para todos los inputs
- **SQL Injection**: Prevenido por Prisma ORM
- **XSS**: Sanitización global de requests

### 4.2 Prevención de Ataques

#### 4.2.1 Timing Attacks
```javascript
// Siempre ejecutar bcrypt incluso si usuario no existe
const dummyHash = '$2b$12$...';
await bcrypt.compare(password, user?.PasswordHash || dummyHash);
await new Promise(resolve => setTimeout(resolve, 1000));
```

#### 4.2.2 CSRF
- Sessions con `sameSite: 'strict'`
- Tokens anti-CSRF (recomendado implementar)

#### 4.2.3 Clickjacking
- `X-Frame-Options: DENY` vía Helmet

#### 4.2.4 Session Fixation
- Regeneración de sesión en login
- Cookie name genérico (`sessionId`)

#### 4.2.5 Brute Force
- Rate limiting por IP
- Rate limiting por IP + username
- Lockout temporal después de intentos fallidos

### 4.3 Auditoría y Logging

#### 4.3.1 Eventos Auditados
- Login exitoso/fallido
- Creación/eliminación de usuarios
- Cambios de contraseña
- Asignación/remoción de roles
- Modificación de órdenes
- Generación de facturas
- Accesos denegados

#### 4.3.2 Información Registrada
```javascript
{
  action: 'USER_CREATED',
  performedBy: { userId, username, roles },
  target: { ... },
  timestamp: ISO 8601,
  ip: req.ip,
  userAgent: req.get('user-agent')
}
```

### 4.4 Protecciones Especiales

#### 4.4.1 Usuario Administrador Principal
```javascript
const PROTECTED_USER_ID = 1;
if (userIdNum === PROTECTED_USER_ID) {
  throw new Error('No se puede eliminar el administrador principal');
}
```

#### 4.4.2 Auto-Eliminación
```javascript
if (userIdNum === req.auth.userId) {
  throw new Error('No puedes eliminar tu propia cuenta');
}
```

#### 4.4.3 Remoción de Rol Propio
```javascript
if (action === 'remove' && 
    roleName === 'Administrador' && 
    userId === req.auth.userId) {
  throw new Error('No puedes remover tu propio rol de administrador');
}
```

### 4.5 Recomendaciones de Seguridad Adicionales

#### 4.5.1 Implementar
- Token blacklist para logout forzado
- 2FA obligatorio para administradores
- Encriptación de datos sensibles en BD
- Rotación automática de secrets
- Detección de anomalías con ML
- Honeypot endpoints para detectar bots

#### 4.5.2 Monitoreo
- Alertas de múltiples logins fallidos
- Notificación de cambios críticos
- Detección de accesos desde ubicaciones inusuales
- Análisis de patrones de uso anómalo

#### 4.5.3 Compliance
- GDPR: Derecho al olvido, portabilidad de datos
- PCI DSS: Si se procesan pagos
- Ley de Protección de Datos Ecuador

---

## 5. Configuración de Servidor

### 5.1 Requisitos del Sistema

#### 5.1.1 Software Requerido

Node.js 18.x o superior
PM2 (Process Manager)
Apache 2.4.x
Base de datos (PostgreSQL/MySQL/SQL Server)
Git (para despliegue)


#### 5.1.2 Dependencias del Sistema
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y curl build-essential

# Windows Server
# Instalar Node.js desde nodejs.org
# Instalar Visual Studio Build Tools
```

### 5.2 Instalación con PM2

#### 5.2.1 Instalación Global de PM2
```bash
npm install -g pm2
```

#### 5.2.2 Configuración PM2 Ecosystem
Crear `ecosystem.config.js`:
```javascript
module.exports = {
  apps: [{
    name: 'ecuatechnology-api',
    script: './index.js',
    instances: 'max',  // Modo cluster
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    error_file: './logs/pm2-error.log',
    out_file: './logs/pm2-out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true,
    watch: false,
    max_memory_restart: '1G',
    min_uptime: '10s',
    max_restarts: 10,
    autorestart: true
  }]
};
```

#### 5.2.3 Comandos PM2 Esenciales
```bash
# Iniciar aplicación
pm2 start ecosystem.config.js

# Detener aplicación
pm2 stop ecuatechnology-api

# Reiniciar aplicación
pm2 restart ecuatechnology-api

# Recargar sin downtime
pm2 reload ecuatechnology-api

# Ver logs en tiempo real
pm2 logs ecuatechnology-api

# Monitorear recursos
pm2 monit

# Listar procesos
pm2 list

# Información detallada
pm2 show ecuatechnology-api

# Eliminar proceso
pm2 delete ecuatechnology-api

# Guardar configuración actual
pm2 save

# Configurar inicio automático
pm2 startup
# Ejecutar el comando que PM2 sugiere
```

#### 5.2.4 Monitoreo con PM2 Plus (Opcional)
```bash
# Registrar en PM2 Plus
pm2 plus

# Link de aplicación
pm2 link <secret-key> <public-key>
```

### 5.3 Configuración de Apache 2.4

#### 5.3.1 Habilitar Módulos Requeridos
```bash
# Linux
sudo a2enmod proxy
sudo a2enmod proxy_http
sudo a2enmod proxy_wstunnel
sudo a2enmod ssl
sudo a2enmod headers
sudo a2enmod rewrite
sudo systemctl restart apache2

# Windows (httpd.conf)
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_wstunnel_module modules/mod_proxy_wstunnel.so
LoadModule ssl_module modules/mod_ssl.so
LoadModule headers_module modules/mod_headers.so
LoadModule rewrite_module modules/mod_rewrite.so
```

#### 5.3.2 Configuración VirtualHost HTTP
Crear `/etc/apache2/sites-available/ecuatechnology-api.conf`:
```apache
<VirtualHost *:80>
    ServerName api.ecuatechnology.com
    ServerAdmin admin@ecuatechnology.com

    # Redirección a HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]

    ErrorLog ${APACHE_LOG_DIR}/ecuatechnology-api-error.log
    CustomLog ${APACHE_LOG_DIR}/ecuatechnology-api-access.log combined
</VirtualHost>
```

#### 5.3.3 Configuración VirtualHost HTTPS
```apache
<VirtualHost *:443>
    ServerName api.ecuatechnology.com
    ServerAdmin admin@ecuatechnology.com

    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/ecuatechnology.crt
    SSLCertificateKeyFile /etc/ssl/private/ecuatechnology.key
    SSLCertificateChainFile /etc/ssl/certs/ecuatechnology-chain.crt

    # SSL Protocol Configuration
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
    SSLHonorCipherOrder on

    # Headers de Seguridad
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    # Proxy Configuration
    ProxyPreserveHost On
    ProxyRequests Off
    ProxyTimeout 300

    # Proxy Pass a Node.js
    ProxyPass / http://localhost:3000/
    ProxyPassReverse / http://localhost:3000/

    # WebSocket Support (si se necesita)
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "ws://localhost:3000/$1" [P,L]

    # Compression
    <IfModule mod_deflate.c>
        AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css text/javascript application/javascript application/json
    </IfModule>

    # Logs
    ErrorLog ${APACHE_LOG_DIR}/ecuatechnology-api-ssl-error.log
    CustomLog ${APACHE_LOG_DIR}/ecuatechnology-api-ssl-access.log combined
</VirtualHost>
```

#### 5.3.4 Habilitar Sitio
```bash
# Linux
sudo a2ensite ecuatechnology-api.conf
sudo apache2ctl configtest
sudo systemctl reload apache2

# Windows
# Incluir configuración en httpd.conf o httpd-vhosts.conf
# Reiniciar Apache desde Services
```

### 5.4 Variables de Entorno

#### 5.4.1 Archivo .env de Producción
```env
# Entorno
NODE_ENV=production

# Servidor
PORT=3000
HOST=0.0ReintentarMContinuar.0.0
Base de Datos
DATABASE_URL="postgresql://user:password@localhost:5432/ecuatechnology"
JWT
JWT_SECRET="tu-secreto-super-seguro-cambialo-en-produccion"
JWT_EXPIRES_IN=8h
Bcrypt
BCRYPT_ROUNDS=12
Session
SESSION_SECRET="otro-secreto-muy-seguro-para-sessions"
Frontend URLs
URL_FRONTEND_WEB=https://portal.ecuatechnology.com
URL_FRONTEND_DESK=https://app.ecuatechnology.com
Email SMTP
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=noreply@ecuatechnology.com
SMTP_PASS=tu-password-smtp
Email Zimbra (alternativo)
ZIMBRA_HOST=mail.ecuatechnology.com
ZIMBRA_PORT=465
ZIMBRA_USER=noreply@ecuatechnology.com
ZIMBRA_PASS=tu-password-zimbra
EMAIL_FROM="Ecuatechnology noreply@ecuatechnology.com"
Admin IT
IT_ADMIN_EMAIL=admin-it@ecuatechnology.com
Cliente App URL (para emails)
CLIENT_APP_URL=https://portal.ecuatechnology.com
STAFF_APP_URL=https://app.ecuatechnology.com

#### 5.4.2 Seguridad de Variables
```bash
# Permisos restrictivos
chmod 600 .env

# Nunca commitear a Git
echo ".env" >> .gitignore

# Usar secrets manager en producción (AWS Secrets Manager, Azure Key Vault)
```

### 5.5 Script de Despliegue

#### 5.5.1 deploy.sh
```bash
#!/bin/bash
set -e

echo "==================================="
echo "Despliegue Ecuatechnology API"
echo "==================================="

# Variables
APP_NAME="ecuatechnology-api"
APP_DIR="/var/www/ecuatechnology-api"
BRANCH="main"

# Actualizar código
echo "[1/6] Actualizando código desde Git..."
cd $APP_DIR
git fetch origin
git checkout $BRANCH
git pull origin $BRANCH

# Instalar dependencias
echo "[2/6] Instalando dependencias..."
npm ci --production

# Ejecutar migraciones
echo "[3/6] Ejecutando migraciones de base de datos..."
npx prisma migrate deploy

# Generar Prisma Client
echo "[4/6] Generando Prisma Client..."
npx prisma generate

# Reiniciar aplicación
echo "[5/6] Reiniciando aplicación con PM2..."
pm2 reload $APP_NAME --update-env

# Verificar estado
echo "[6/6] Verificando estado..."
sleep 3
pm2 list
pm2 logs $APP_NAME --lines 20 --nostream

echo "==================================="
echo "Despliegue completado exitosamente"
echo "==================================="
```

#### 5.5.2 Permisos de Ejecución
```bash
chmod +x deploy.sh
```

### 5.6 Backup y Recuperación

#### 5.6.1 Script de Backup
```bash
#!/bin/bash
BACKUP_DIR="/backups/ecuatechnology"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup de Base de Datos
pg_dump -U postgres ecuatechnology > "$BACKUP_DIR/db_$DATE.sql"

# Backup de Archivos (facturas, etc.)
tar -czf "$BACKUP_DIR/files_$DATE.tar.gz" /var/www/ecuatechnology-api/storage

# Mantener solo últimos 30 días
find $BACKUP_DIR -name "*.sql" -mtime +30 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

echo "Backup completado: $DATE"
```

#### 5.6.2 Cron para Backup Automático
```bash
# Editar crontab
crontab -e

# Backup diario a las 2:00 AM
0 2 * * * /opt/scripts/backup.sh >> /var/log/backup.log 2>&1
```

### 5.7 Monitoreo y Salud

#### 5.7.1 Health Check Endpoint
```javascript
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});
```

#### 5.7.2 Monitoreo con Uptime Robot
URL: https://api.ecuatechnology.com/health
Intervalo: 5 minutos
Tipo: HTTP(s)
Keyword: "ok"

#### 5.7.3 Alertas
```bash
# Configurar alertas PM2
pm2 install pm2-logrotate
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 30
```

---

## 6. Consideraciones Futuras

### 6.1 Migración a Prisma 7

#### 6.1.1 Cambios Esperados
- **Prisma Client**: API más tipada y performante
- **Prisma Migrate**: Mejoras en diff y rollback
- **Prisma Studio**: Interfaz mejorada
- **Performance**: Query optimization automático

#### 6.1.2 Plan de Migración
```bash
# 1. Actualizar Prisma CLI
npm install -g prisma@7

# 2. Actualizar dependencias del proyecto
npm install prisma@7 @prisma/client@7

# 3. Generar nuevo Prisma Client
npx prisma generate

# 4. Probar en entorno de desarrollo
npm run dev

# 5. Ejecutar tests
npm test

# 6. Desplegar en staging
# 7. Monitorear por 48 horas
# 8. Desplegar en producción
```

#### 6.1.3 Breaking Changes a Verificar
- Cambios en API de queries
- Deprecación de métodos antiguos
- Nuevos tipos de datos
- Cambios en formato de migración

### 6.2 Escalabilidad

#### 6.2.1 Arquitectura de Microservicios
Actual: Monolito modular
Futuro:

API Gateway
Auth Service
Order Service
Invoice Service
Notification Service
Ticket Service


#### 6.2.2 Caché
Implementar:

Redis para sessions
Redis para caché de queries frecuentes
CDN para assets estáticos


#### 6.2.3 Cola de Mensajes
Implementar:

Bull/BullMQ para jobs async
RabbitMQ para comunicación entre servicios
Kafka para event streaming


### 6.3 Base de Datos

#### 6.3.1 Optimizaciones
```sql
-- Índices adicionales recomendados
CREATE INDEX idx_order_client ON ServiceOrder(ClientId);
CREATE INDEX idx_order_status ON ServiceOrder(CurrentStatusId);
CREATE INDEX idx_ticket_client ON Ticket(ClientId);
CREATE INDEX idx_ticket_status ON Ticket(Status);
CREATE INDEX idx_invoice_order ON Invoice(OrderId);
```

#### 6.3.2 Particionamiento
Para tablas grandes:

OrderStatusHistory por fecha
Logs por mes
Tickets antiguos a tabla histórica


#### 6.3.3 Replicación
Master-Slave:

Master: Escrituras
Slaves: Lecturas (reportes, consultas)


### 6.4 Seguridad Avanzada

#### 6.4.1 WAF (Web Application Firewall)
Implementar:

ModSecurity con Apache
CloudFlare WAF
AWS WAF


#### 6.4.2 SIEM (Security Information and Event Management)
Integrar:

Splunk
ELK Stack (Elasticsearch, Logstash, Kibana)
Graylog


#### 6.4.3 Penetration Testing
Realizar:

Tests de penetración trimestrales
Vulnerability scanning automático
Code security analysis (SonarQube, Snyk)


### 6.5 Cumplimiento Normativo

#### 6.5.1 SRI Ecuador

Integración automática con SRI
Firma electrónica PKCS#12
Autorización en tiempo real
Reporte de retenciones


#### 6.5.2 GDPR / Protección de Datos

Implementar derecho al olvido
Portabilidad de datos
Consentimiento explícito
Data retention policies


### 6.6 Mejoras Funcionales

#### 6.6.1 Integraciones

Pasarelas de pago (PayPhone, Datafast)
Servicios de mensajería (WhatsApp Business API)
ERP/CRM externos
Firma electrónica


#### 6.6.2 Analytics

Google Analytics
Mixpanel para eventos
Dashboard de BI
Reportes automáticos


#### 6.6.3 Mobile Apps

API mobile-first
Push notifications
Offline mode
Deep linking


### 6.7 DevOps

#### 6.7.1 CI/CD
```yaml
# GitHub Actions ejemplo
name: Deploy Production
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: npm test
      - name: Deploy
        run: ./deploy.sh
```

#### 6.7.2 Containerización
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
RUN npx prisma generate
EXPOSE 3000
CMD ["node", "index.js"]
```

#### 6.7.3 Orquestación
Kubernetes:

Deployment para API
Service para load balancing
ConfigMap para configuración
Secrets para credenciales
Ingress para routing


### 6.8 Documentación

#### 6.8.1 API Documentation
Implementar:

Swagger/OpenAPI 3.0
Postman Collections
API versioning


#### 6.8.2 Developer Portal
Crear:

Guías de integración
Code samples
SDK clients
Changelog


---

## 7. Anexos

### 7.1 Comandos Útiles

#### 7.1.1 Prisma
```bash
# Generar migración
npx prisma migrate dev --name nombre_migracion

# Aplicar migraciones
npx prisma migrate deploy

# Resetear BD (desarrollo)
npx prisma migrate reset

# Abrir Prisma Studio
npx prisma studio

# Formatear schema
npx prisma format

# Validar schema
npx prisma validate
```

#### 7.1.2 PM2
```bash
# Ver logs con filtro
pm2 logs ecuatechnology-api --lines 100 | grep ERROR

# Exportar configuración
pm2 ecosystem

# Flush logs
pm2 flush

# Reinicio programado
pm2 restart ecuatechnology-api --cron "0 2 * * *"
```

#### 7.1.3 Apache
```bash
# Test configuración
sudo apache2ctl configtest

# Ver errores
tail -f /var/log/apache2/error.log

# Ver accesos
tail -f /var/log/apache2/access.log

# Reload sin downtime
sudo systemctl reload apache2
```

### 7.2 Troubleshooting

#### 7.2.1 Aplicación no inicia
```bash
# Verificar logs
pm2 logs ecuatechnology-api --err

# Verificar puerto ocupado
lsof -i :3000

# Verificar variables de entorno
pm2 env 0

# Reiniciar desde cero
pm2 delete ecuatechnology-api
pm2 start ecosystem.config.js
```

#### 7.2.2 Errores de Base de Datos
```bash
# Verificar conexión
npx prisma db pull

# Ver estado migraciones
npx prisma migrate status

# Resolver conflictos
npx prisma migrate resolve --applied "nombre_migracion"
```

#### 7.2.3 Problemas de Performance
```bash
# Ver uso de CPU/Memoria
pm2 monit

# Ver queries lentas (PostgreSQL)
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;

# Analizar query específica
EXPLAIN ANALYZE SELECT ...;
```

---

## Conclusión

Este documento técnico proporciona una visión completa del backend del Sistema Ecuatechnology, cubriendo arquitectura, seguridad, configuración de servidor y consideraciones futuras. La implementación actual establece una base sólida con autenticación híbrida, control de acceso basado en roles, facturación electrónica y sistema de tickets de soporte.

Las recomendaciones de mejora y planes futuros aseguran que el sistema pueda escalar y adaptarse a nuevos requerimientos mientras mantiene altos estándares de seguridad y rendimiento.

**Versión del Documento**: 1.0  
**Fecha**: Noviembre 2024  
**Autor**: Equipo de Desarrollo Ecuatechnology  
**Contacto**: dev@ecuatechnology.com
