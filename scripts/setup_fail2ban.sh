#!/bin/bash

# Atualiza pacotes e instala o Fail2Ban
sudo apt update
sudo apt install fail2ban -y

# Cria a configuração do jail.local para proteger o SSH
sudo bash -c 'cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF'

# Habilita o serviço para iniciar com o sistema e reinicia para aplicar a configuração
sudo systemctl enable fail2ban
sudo systemctl restart fail2ban
