#!/bin/bash
# Configura o PQC (Post-Quantum Cryptography) e HSTS no arquivo de configuração real do Nginx no servidor

NGINX_CONF_DIR="/etc/nginx/sites-available"

# Identifica qual arquivo está sendo usado (app ou default)
if [ -f "$NGINX_CONF_DIR/app" ]; then
    CONF_FILE="$NGINX_CONF_DIR/app"
elif [ -f "$NGINX_CONF_DIR/default" ]; then
    CONF_FILE="$NGINX_CONF_DIR/default"
else
    echo "Arquivo de configuração do Nginx não encontrado em sites-available."
    exit 0
fi

echo "Atualizando configuração do Nginx em: $CONF_FILE"

# 1. Adicionar HSTS (Strict-Transport-Security) se não existir
if ! grep -q "Strict-Transport-Security" "$CONF_FILE"; then
    sudo sed -i '/ssl_protocols/i \    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;' "$CONF_FILE"
fi

# 2. Configurar o ssl_ecdh_curve para PQC (KyberDraft00)
PQC_CURVE="ssl_ecdh_curve X25519Kyber768Draft00:X25519:secp384r1;"

if ! grep -q "ssl_ecdh_curve" "$CONF_FILE"; then
    sudo sed -i "/ssl_protocols/i \    $PQC_CURVE" "$CONF_FILE"
else
    # Se já existir, substitui para garantir que está com as curvas certas
    sudo sed -i "s/ssl_ecdh_curve.*/$PQC_CURVE/g" "$CONF_FILE"
fi

# 3. Consertar o erro do /etc/nginx/nginx.conf global corrompido
# Se o arquivo global tiver o certificado self-signed da tentativa anterior, ele está quebrado e conflitando
if grep -q "nginx-selfsigned.crt" /etc/nginx/nginx.conf; then
    echo "Restaurando o /etc/nginx/nginx.conf para o padrão do Ubuntu..."
    sudo bash -c 'cat > /etc/nginx/nginx.conf <<EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    gzip on;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF'
fi

# 4. Validar e recarregar o Nginx
sudo nginx -t && sudo systemctl reload nginx
