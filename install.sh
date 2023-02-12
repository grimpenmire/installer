#!/bin/bash

set -e

# check for effective root
if [ "$EUID" -ne 0 ]; then
    echo "Not root."
    exit 1
fi

# check required variables
if [ -z "${DOMAIN}" ]; then
    echo "DOMAIN variable not set."
    exit 1
fi

# variables with defaults
FORCE_CERT=${FORCE_CERT:-}  # set to a value if you want to obtain certificate
                            # even if it already exists
CERT_EMAIL=${CERT_EMAIL:-mahsa@grimpen.one}
DOMAIN=${DOMAIN:-arafel.online}
SECRET="${SECRET:-$(openssl rand -hex 16)}"
TG_FAKETLS_DOMAIN=${TG_FAKETLS_DOMAIN:-ubuntu.com}

# derivative variables
TG_HEX_DOMAIN=$(echo -n "$TG_FAKETLS_DOMAIN" | xxd -p | tr -d '\n')
TG_SECRET="ee${SECRET}${TG_HEX_DOMAIN}"

echo "Checking DNS records..."
DOMAIN_IP=$(dig +short ${DOMAIN} | tr -d '\n')
SERVER_IP=$(curl -s https://ipinfo.io/ip)
if [ "${DOMAIN_IP}" != "${SERVER_IP}" ]; then
    echo "DNS record does not match server ip."
    echo "${DOMAIN} points to: ${DOMAIN_IP}"
    echo "Server ip is: ${SERVER_IP}"
    exit 1
fi

apt update
apt install -y nginx certbot python3-certbot-nginx unzip dnsutils

if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" -a ! "${FORCE_CERT}" ]; then
    echo "Certificate already exists."
else
    echo "Obtaining TLS certificate..."
    certbot certonly --nginx -d ${DOMAIN} -w /var/www/html -m ${CERT_EMAIL} --non-interactive --agree-tos
fi

echo "Installing mtg..."
rm -rf /tmp/mtg.tar.gz /tmp/mtg-2.1.7-linux-amd64
curl -sL https://github.com/9seconds/mtg/releases/download/v2.1.7/mtg-2.1.7-linux-amd64.tar.gz -o /tmp/mtg.tar.gz
tar -C /tmp -xf /tmp/mtg.tar.gz
mv /tmp/mtg-2.1.7-linux-amd64/mtg /usr/local/bin/mtg
rm -r /tmp/mtg.tar.gz /tmp/mtg-2.1.7-linux-amd64
cat >/etc/systemd/system/mtg.service <<EOF
[Unit]
Description=mtg - MTProto proxy server
Documentation=https://github.com/9seconds/mtg
After=network.target

[Service]
ExecStart=/usr/local/bin/mtg run /etc/mtg.toml
Restart=always
RestartSec=3
DynamicUser=true
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
cat >/etc/mtg.toml <<EOF
secret = "${TG_SECRET}"
bind-to = "127.0.0.1:2001"
EOF
systemctl daemon-reload
systemctl enable mtg
systemctl start mtg

echo "Installing trojan-go..."
rm -rf /tmp/trojan-go.zip /tmp/trojan-go
curl -sL https://github.com/p4gefau1t/trojan-go/releases/download/v0.10.6/trojan-go-linux-amd64.zip -o /tmp/trojan-go.zip
mkdir /tmp/trojan-go
cd /tmp/trojan-go && unzip ../trojan-go.zip && cd -
mv /tmp/trojan-go/trojan-go /usr/local/bin/
cat >/etc/systemd/system/trojan-go.service <<EOF
[Unit]
Description=Trojan-Go - An unidentifiable mechanism that helps you bypass GFW
Documentation=https://p4gefau1t.github.io/trojan-go/
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/trojan-go -config /etc/trojan-go.json
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
cat >/etc/trojan-go.json <<EOF
{
  "run_type": "server",
  "local_addr": "127.0.0.1",
  "local_port": 2002,
  "remote_addr": "127.0.0.1",
  "remote_port": 80,
  "password": ["jina"],
  "ssl": {
    "cert": "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem",
    "key": "/etc/letsencrypt/live/${DOMAIN}/privkey.pem",
    "sni": "${DOMAIN}"
  },
  "websocket": {
    "enabled": true,
    "path": "/${SECRET}/trojan-go",
    "hostname": "${DOMAIN}"
  },
  "mux": {
    "enabled": true
  }
}
EOF
rm -r /tmp/trojan-go.zip /tmp/trojan-go
systemctl daemon-reload
systemctl enable trojan-go
systemctl start trojan-go

cat >/etc/nginx/nginx.conf <<EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;

load_module /usr/lib/nginx/modules/ngx_stream_module.so;

events {
    worker_connections 768;
}

stream {
    map \$ssl_preread_server_name \$upstream_name {
        ubuntu.com mtproto;
        default web;
    }

    log_format main '\$remote_addr - time=[\$time_local] - '
                    'upstream=\$upstream_name sni=\$ssl_preread_server_name';
    access_log /var/log/nginx/stream.log main;

    server {
        listen 443;
        ssl_preread on;
        proxy_pass \$upstream_name;
    }

    upstream mtproto {
        server 127.0.0.1:2001;
    }

    upstream web {
        server 127.0.0.1:8443;
    }
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    server {
        listen 8443 ssl http2;
        ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

        location /${SECRET}/trojan-go {
            proxy_redirect off;
            proxy_http_version 1.1;
            proxy_pass https://127.0.0.1:2002;
            proxy_ssl_server_name on;
            proxy_ssl_name \$http_host;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }

        location /${SECRET}/dns-cf {
            proxy_pass https://cloudflare-dns.com/dns-query;
        }

        location / {
            proxy_pass http://127.0.0.1:80;
        }
    }

    server {
        listen 80;
        root /var/www/html;

        location / {
        }
    }
}
EOF
systemctl reload nginx

echo "Secret: ${SECRET}"
echo "TG Proxy: tg://proxy?server=${DOMAIN}&port=443&secret=${TG_SECRET}"
echo "Trojan-Go: trojan-go://jina@${DOMAIN}:443?encryption=none&host=${DOMAIN}&path=%2F${SECRET}%2Ftrojan-go&sni=${DOMAIN}&type=ws"

echo "Done."
