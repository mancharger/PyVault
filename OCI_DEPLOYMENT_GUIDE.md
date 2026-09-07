# Guia de Implantação Seguro - OCI Free Tier (Ubuntu)

Este guia detalha o passo a passo para configurar uma máquina virtual na Oracle Cloud Infrastructure (OCI) aplicando os princípios de **Secure by Design** e **Secure by Default**, para hospedar a aplicação do projeto de forma segura e com suporte às exigências mais recentes, como certificados IP Let's Encrypt e Criptografia Pós-Quântica (PQC).

## 1. Criação da VM na OCI e Acesso SSH
Ao criar sua Instância Compute na OCI (recomenda-se **Ubuntu 24.04 LTS** no Free Tier):
1. **Gere um par de chaves SSH localmente** (caso não tenha):
   ```bash
   ssh-keygen -t ed25519 -C "admin_oci"
   ```
2. Na etapa de criação da VM na OCI, **faça o upload da chave pública** (`id_ed25519.pub`).
3. Conecte-se à VM utilizando a chave privada:
   ```bash
   ssh -i /caminho/para/chave_privada ubuntu@<IP_PUBLICO_DA_VM>
   ```

### 1.1 Desabilitar Autenticação por Senha (Hardening do SSH)
O Ubuntu na OCI normalmente já vem com senha desabilitada, mas é essencial garantir.
Edite o arquivo de configuração do SSH:
```bash
sudo nano /etc/ssh/sshd_config
```
Certifique-se de que as seguintes diretivas estejam assim:
```ini
PasswordAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
```
Reinicie o serviço SSH:
```bash
sudo systemctl restart ssh
```

## 2. Firewall e Security Groups (Least Privilege)

A segurança de rede deve ser feita em duas camadas: na infraestrutura da OCI e no SO (UFW).

### 2.1 OCI VCN (Security Lists)
No painel da Oracle Cloud:
1. Vá em **Networking** > **Virtual Cloud Networks** > Sua VCN > **Security List**.
2. Remova regras desnecessárias.
3. Adicione Regras de Entrada (Ingress Rules) apenas para:
   - **TCP 22** (SSH) - *Se possível, restrinja para o seu IP fixo de origem.*
   - **TCP 80** (HTTP) - Apenas para renovação Let's Encrypt e redirecionamento.
   - **TCP 443** (HTTPS) - Tráfego da aplicação.

### 2.2 UFW (Uncomplicated Firewall) no SO
Configure o firewall local para permitir apenas o estritamente necessário:
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## 3. Proteção do SSH com Fail2Ban

O `fail2ban` monitorará os logs do SSH e banirá IPs com múltiplas tentativas falhas de login.

1. Instale o Fail2Ban:
   ```bash
   sudo apt update && sudo apt install fail2ban -y
   ```
2. Crie a configuração local copiando o padrão:
   ```bash
   sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
   sudo nano /etc/fail2ban/jail.local
   ```
3. Configure o *jail* do `sshd` no arquivo (geralmente na seção `[sshd]`) com os parâmetros exigidos:
   ```ini
   [sshd]
   enabled = true
   port    = 22
   filter  = sshd
   logpath = /var/log/auth.log
   maxretry = 4
   bantime = 24h
   findtime = 10m
   ```
4. Reinicie o serviço:
   ```bash
   sudo systemctl enable fail2ban
   sudo systemctl restart fail2ban
   ```

## 4. Servidor Web (Nginx) e TLS com PQC / Qualys A

Para o servidor web e proxy reverso, utilizaremos o **Nginx**.

1. Instale o Nginx:
   ```bash
   sudo apt install nginx -y
   ```

### 4.1 Certbot 5.4+ (Certificado para IP Público Let's Encrypt)
A partir de janeiro de 2026, a Let's Encrypt permite emitir certificados diretamente para IPs públicos.
1. Instale o Certbot (certifique-se de que é a versão 5.4+ via snap):
   ```bash
   sudo snap install core; sudo snap refresh core
   sudo snap install --classic certbot
   sudo ln -s /snap/bin/certbot /usr/bin/certbot
   ```
2. Solicite o certificado para o IP:
   ```bash
   sudo certbot certonly --nginx -d <SEU_IP_PUBLICO> --agree-tos --no-eff-email -m seu_email@exemplo.com
   ```
   *O Certbot criará um temporizador de auto-renovação automaticamente (`systemctl status certbot.timer`).*

### 4.2 Configuração Nginx com HTTPS e PQC
O Nginx deve redirecionar HTTP para HTTPS e suportar Criptografia Pós-Quântica (via `ssl_ecdh_curve`).

Edite a configuração da aplicação:
```bash
sudo nano /etc/nginx/sites-available/app
```
Insira a configuração segura:

```nginx
# Redirecionamento HTTP para HTTPS
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name <SEU_IP_PUBLICO>;
    return 301 https://$host$request_uri;
}

# Configuração HTTPS Secure by Default & PQC
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name <SEU_IP_PUBLICO>;

    ssl_certificate /etc/letsencrypt/live/<SEU_IP_PUBLICO>/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/<SEU_IP_PUBLICO>/privkey.pem;

    # Protocolos seguros (Desativa TLS 1.0 e 1.1)
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Suporte a Criptografia Pós-Quântica (PQC) - ML-KEM
    # Requer OpenSSL 3.2+ e Nginx recente no Ubuntu 24.04
    ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;

    # Cifras Seguras (Sem dependência do servidor para TLS 1.3, mas útil para 1.2)
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    # Headers de Segurança para nota A no Qualys SSL Labs
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    # Proxy para a aplicação backend/frontend (ex: rodando na porta 8000 interna)
    location / {
        proxy_pass http://127.0.0.1:8000; # Ajuste para a porta do seu Docker Compose / Uvicorn
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Habilite o site e reinicie o Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/app /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
```

## 5. Integração com GitHub para CI/CD

A aplicação deve ser alimentada via repositório. O ideal é que a VM possua acesso de leitura seguro ao repositório via **Deploy Keys**.

1. Na VM, gere uma chave específica para o GitHub:
   ```bash
   ssh-keygen -t ed25519 -C "deploy_oci_vm" -f ~/.ssh/github_deploy_key
   ```
2. Adicione essa chave à configuração local SSH (`~/.ssh/config`):
   ```ini
   Host github.com
       HostName github.com
       IdentityFile ~/.ssh/github_deploy_key
       StrictHostKeyChecking no
   ```
3. Copie o conteúdo da chave pública:
   ```bash
   cat ~/.ssh/github_deploy_key.pub
   ```
4. No GitHub, vá em **Settings do Repositório** > **Deploy Keys** > **Add deploy key**. Cole a chave (permita acesso de leitura).
5. Clone o repositório na pasta desejada (`/var/www/app` ou `~/app`):
   ```bash
   git clone git@github.com:<SEU_USUARIO>/<SEU_REPOSITORIO>.git ~/projeto
   ```
6. **Automação (Opcional, mas recomendado)**: Utilize um webhook via um serviço leve (como `webhook`) ou configure o **GitHub Actions** usando um Runner auto-hospedado (Self-Hosted Runner) na VM, para que um `git pull && docker compose up -d --build` aconteça automaticamente a cada commit na branch `main`.
