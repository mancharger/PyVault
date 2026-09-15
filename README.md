# 🔒 PyVault - Cofre Unificado Zero-Knowledge

O **PyVault** é uma aplicação voltada para segurança da informação baseada no conceito de *Zero-Knowledge* (Conhecimento Zero). O servidor armazena dados criptografados e não possui capacidade de lê-los. 🛡️ Mesmo que um atacante obtenha acesso ao banco de dados ou ao servidor, ele encontrará apenas ruídos (textos embaralhados), garantindo total privacidade e segurança para os dados sensíveis dos usuários. 🕵️‍♂️

---

## 🛡️ Pilares de Segurança do Projeto

Este projeto foi desenvolvido com foco em três frentes principais de cibersegurança e análise forense:

1. **🔐 Criptografia Client-Side (Zero-Knowledge):** A senha mestra do usuário deriva uma chave criptográfica localmente (no navegador/dispositivo) usando o algoritmo **Argon2** (padrão ouro atual). Todos os arquivos e textos são criptografados no cliente usando **AES-256-GCM** antes de serem enviados para a rede.
2. **📜 Trilha Forense (Audit Trail) Imutável:** Todas as interações com o sistema (login falho, tentativa de acesso, alteração de notas) são registradas de forma imutável. Cada log contém Timestamp, IP e Ação. A integridade dos logs é mantida através de *Hash Chaining* (Cadeia de Hashes usando SHA-256), tornando qualquer adulteração imediatamente detectável. 🔗
3. **🚧 Isolamento de Infraestrutura (VCN OCI):** A API desenvolvida em Python (FastAPI) não possui acesso direto à internet. Ela está protegida atrás de um Proxy Reverso (Nginx) que lida com a terminação SSL/TLS (HTTPS) e bloqueia o tráfego não autorizado, aceitando apenas conexões na porta segura (443). 🛡️

---

## 🛠️ Stack Tecnológico

- **Backend:** 🐍 Python, FastAPI (Alta performance, APIs RESTful seguras).
- **Criptografia:** 🔑 `cryptography` (Python) para AES-256-GCM, `passlib` com Argon2, e PyJWT para tokens.
- **Proxy e Isolamento:** 🌐 Nginx (Proxy reverso) e Docker Compose 🐳.
- **Persistência de Dados (Nuvem OCI):** ☁️
  - OCI Autonomous Database (PostgreSQL) - Para metadados e trilha forense.
  - OCI Object Storage - Para armazenar os arquivos/blobs criptografados.
- **Frontend:** 🎨 Design responsivo, voltado para *dark mode* e padrões modernos de segurança (*glassmorphism*, *cyber-security palette*).

---

## 🛡️ Mitigação de Vulnerabilidades (OWASP Top 10:2025)

Para cumprir os rigorosos requisitos de segurança (Secure by Design), o código previne ativamente as seguintes vulnerabilidades do OWASP Top 10:2025:

1. **A01:2021-Broken Access Control (Quebra de Controle de Acesso):** 
   - **Onde encontrar:** `backend/app/routes/vault.py` e `backend/app/auth.py`.
   - **Como mitiga:** Implementação estrita de tokens JWT para rotas privadas. As consultas no banco de dados usam o `user_id = current_user.id` em todas as rotas de acesso e manipulação de arquivos/notas, garantindo que um usuário logado nunca consiga acessar ou modificar artefatos de outro.

2. **A02:2021-Cryptographic Failures (Falhas Criptográficas):**
   - **Onde encontrar:** `frontend/main.js` (Funções de derivação de chaves).
   - **Como mitiga:** Dados sensíveis são criptografados em trânsito (HTTPS obrigatório e redirecionado pelo Nginx) e em repouso. A aplicação web utiliza o algoritmo de derivação **Argon2** (via WebAssembly) e criptografia simétrica **AES-256-GCM** localmente, gerando *Zero-Knowledge Proof*. Chaves nunca transitam pela rede.

3. **A07:2021-Identification and Authentication Failures (Falhas de Identificação e Autenticação):**
   - **Onde encontrar:** `backend/app/routes/auth.py` (MFA flow) e bloqueio de rotas.
   - **Como mitiga:** Além da derivação forte por Argon2, o sistema implementa obrigatoriamente a **Autenticação de Múltiplos Fatores (MFA / TOTP)**. O login exige a apresentação de um token MFA válido de 6 dígitos para gerar a sessão de acesso, mitigando ataques de *Credential Stuffing* e vazamentos de senhas.

---

## 🔄 Automação e CI/CD (GitHub Actions)

A infraestrutura conta com uma pipeline de entrega contínua (CI/CD) transparente:
- Todo push na branch `main` ativa o workflow configurado em `.github/workflows/deploy.yml`.
- A pipeline aciona o ambiente em nuvem, executa o `git pull` e faz o rebuild da aplicação (via `docker compose`) sem tempo de inatividade prolongado.
- As credenciais de acesso ao servidor estão blindadas através do GitHub Secrets.

---

## 🚀 Como Executar Localmente

### 📌 Pré-requisitos
- [Docker](https://www.docker.com/) 🐳 e Docker Compose instalados no sistema.

### 📝 Passo a Passo

1. **Clone este repositório:**
   ```bash
   git clone https://github.com/mancharger/PyVault.git
   ```
2. **Acesse a pasta do projeto:**
   ```bash
   cd PyVault
   ```
3. **Suba os containers Docker:**
   ```bash
   docker-compose up --build -d
   ```
4. **Pronto! 🎉** A API estará isolada e o servidor Nginx responderá localmente (acesse através do seu navegador).

---
🎓 *Projeto desenvolvido para Pós-Graduação em Segurança da Informação e Análise Forense.*
