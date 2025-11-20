#!/bin/bash
echo "Verificando Node.js..."
node --version

echo "Verificando archivos..."
ls -la

echo "Iniciando aplicación con PM2..."
pm2 delete miapp 2>/dev/null || true
pm2 start index.js --name miapp --watch

echo "Estado actual:"
pm2 status

echo "Últimos logs:"
pm2 logs miapp --lines 10 --nostream