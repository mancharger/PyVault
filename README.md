# PyVault - Cofre Unificado Zero-Knowledge

O **PyVault** é uma aplicação voltada para segurança da informação baseada no conceito de *Zero-Knowledge* (Conhecimento Zero). O servidor armazena dados criptografados e não possui capacidade de lê-los. Mesmo que um atacante obtenha acesso ao banco de dados ou ao servidor, ele encontrará apenas ruídos (textos embaralhados), garantindo total privacidade e segurança para os dados sensíveis dos usuários.

## Pilares de Segurança do Projeto

Este projeto foi desenvolvido com foco em três frentes principais de cibersegurança e análise forense:

1. **Criptografia Client-Side (Zero-Knowledge):** A senha mestra do usuário deriva uma chave criptográfica localmente (no navegador/dispositivo) usando o algoritmo **Argon2** (padrão ouro atual). Todos os arquivos e textos são criptografados no cliente usando **AES-256-GCM** antes de serem enviados para a rede.
2. **Trilha Forense (Audit Trail) Imutável:** Todas as interações com o sistema (login falho, tentativa de acesso, alteração de notas) são registradas de forma imutável. Cada log contém Timestamp, IP e Ação. A integridade dos logs é mantida através de *Hash Chaining* (Cadeia de Hashes usando SHA-256), tornando qualquer adulteração imediatamente detectável.
3. **Isolamento de Infraestrutura (VCN OCI):** A API desenvolvida em Python (FastAPI) não possui acesso direto à internet. Ela está protegida atrás de um Proxy Reverso (Nginx) que lida com a terminação SSL/TLS (HTTPS) e bloqueia o tráfego não autorizado, aceitando apenas conexões na porta segura (443).

## Stack Tecnológico

- **Backend:** Python, FastAPI (Alta performance, APIs RESTful seguras).
- **Criptografia:** cryptography (Python) para AES-256-GCM, passlib com Argon2, e PyJWT para tokens.
- **Proxy e Isolamento:** Nginx (Proxy reverso) e Docker Compose.
- **Persistência de Dados (Nuvem OCI):**
  - OCI Autonomous Database (PostgreSQL) - Para metadados e trilha forense.
  - OCI Object Storage - Para armazenar os arquivos/blobs criptografados.
- **Frontend:** Design responsivo, voltado para *dark mode* e padrões modernos de segurança (*glassmorphism*, *cyber-security palette*).

## Como Executar Localmente

### Pré-requisitos
- [Docker](https://www.docker.com/) e Docker Compose instalados no sistema.

### Passo a Passo

1. Clone este repositório:
   `ash
   git clone https://github.com/mancharger/PyVault.git
   `
2. Acesse a pasta do projeto:
   `ash
   cd PyVault
   `
3. Suba os containers Docker:
   `ash
   docker-compose up --build -d
   `
4. A API estará isolada e o servidor Nginx responderá localmente.

---
*Projeto desenvolvido para Pós-Graduação em Segurança da Informação e Análise Forense.*
