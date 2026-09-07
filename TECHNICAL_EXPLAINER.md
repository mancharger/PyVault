# PyVault: Architecture & Security Overview

## 1. Resumo Executivo
O **PyVault** é uma solução de armazenamento seguro e unificado estruturada estritamente sob o paradigma **Zero-Knowledge (ZK)**. Concebido primariamente para ambientes de alta sensibilidade, a arquitetura assegura que a infraestrutura de backend (servidor e banco de dados) opere como um *blind datastore*, desprovida do material criptográfico necessário para decifrar os *payloads* armazenados. Este modelo mitiga riscos de exfiltração de dados em cenários de comprometimento total do servidor (Data Breach) ou acesso não autorizado à infraestrutura em nuvem.

## 2. Threat Model & Postura de Segurança
O projeto endereça as seguintes superfícies de ataque:
- **Comprometimento de Banco de Dados:** Mitigado por encriptação determinística e autenticada *client-side*.
- **Interceptação de Tráfego (Man-in-the-Middle):** Mitigado por TLS (via Nginx reverse proxy) e isolamento dentro de uma Virtual Cloud Network (VCN).
- **Tampering de Logs (Evasão Forense):** Endereçado pela implementação de *Hash Chaining* na trilha de auditoria, garantindo imutabilidade e não repúdio.
- **Ataques de Força Bruta / Dicionário em Chaves:** Mitigado por funções de derivação de chave com alto custo computacional e resistência a paralelização (Argon2).

## 3. Implementação Criptográfica

### 3.1. Key Derivation Function (KDF)
A chave de encriptação primária (*Data Encryption Key* - DEK) não é transmitida em momento algum. Ela é derivada *client-side* a partir da *Master Password* do usuário combinada a um salt único.
- **Algoritmo:** Argon2 (padrão-ouro reconhecido pelo PHC - Password Hashing Competition).
- **Vetor de Ataque Mitigado:** *Time-memory trade-off attacks* (TMTO) e paralelização excessiva por ASICs/GPUs.
- **Mecanismo:** A derivação ocorre localmente. O servidor recebe apenas um token de prova de posse (autenticação JWT), segregando inteiramente a chave de cifragem simétrica da credencial utilizada para controle de acesso (RBAC/ABAC).

### 3.2. Confidencialidade e Integridade de Dados (AEAD)
Os *blobs* de arquivos e textos planos são submetidos a cifras de bloco em modo autenticado antes do trânsito na rede.
- **Cipher Suite:** AES-256 em modo GCM (Galois/Counter Mode).
- **Vantagem Tática:** O GCM provê AEAD (*Authenticated Encryption with Associated Data*). Qualquer tentativa de manipulação de bits (bit-flipping attacks) nos ciphertexts em repouso resultará em falha na tag de autenticação MAC durante a tentativa de decifragem no cliente, acusando imediatamente a corrupção ou adulteração do dado.

## 4. Trilha Forense e Imutabilidade (Audit Trail)

Em estrita conformidade com os requisitos de Análise Forense, o PyVault implementa um registro imutável de eventos transacionais (Log Trail) fundamental para processos de Incident Response (IR).

### 4.1. Arquitetura de Hash Chaining
A integridade da tabela de auditoria não depende apenas de restrições lógicas do SGBD (RBAC), mas de sólidas garantias criptográficas:
- Todo evento $E_n$ (e.g., `AUTH_FAILURE`, `FILE_ACCESS`, `NOTE_UPDATE`) é submetido a uma função de hash criptográfico.
- **Função de Hash:** SHA-256.
- **Encadeamento Estrutural:** O hash do log atual $H(E_n)$ é computado utilizando o conteúdo serializado do próprio log acrescido do hash do registro cronológico imediatamente anterior $H(E_{n-1})$. Formulação: $H(E_n) = \text{SHA-256}(Data_n \parallel H(E_{n-1}))$.
- **Garantia Forense:** A exclusão, modificação ou inserção retroativa de qualquer registro na base invalida criptograficamente toda a cadeia subsequente (*chain breakdown*). Isso atua como um *Tripwire* matemático, inviabilizando tentativas de encobrimento de rastros por agentes de ameaça (Threat Actors).

## 5. Isolamento de Infraestrutura e Rede (OCI)

A topologia de rede foi desenhada sob os princípios de *Defense in Depth* e *Zero Trust Architecture (ZTA)*.

- **Virtual Cloud Network (VCN):** A API (FastAPI) reside segregada. Não possui rotas diretas para a internet pública (ausência de Internet Gateway ou IP público direto).
- **Reverse Proxying & TLS Termination:** O Nginx atua como ponto único de entrada (*Single Point of Entry*) em uma sub-rede configurada, realizando a terminação da camada SSL/TLS e repassando o tráfego validado para o backend na porta HTTPS/443 local.
- **Camada de Persistência:** A infraestrutura utiliza o ecossistema Oracle Cloud Infrastructure (OCI). Bancos relacionais (como PostgreSQL) para trilhas estruturadas e OCI Object Storage para o armazenamento dos blobs cifrados de forma distribuída e escalável.

## 6. Stack Tecnológico Fundamental
- **Backend API:** Python 3.x implementando `FastAPI` (Servidor ASGI assíncrono de alta performance).
- **Criptografia Aplicada:** Biblioteca `cryptography` nativa do Python (para AES-256-GCM), `passlib` (para gestão robusta de KDF/Argon2) e autenticação stateless baseada em `PyJWT`.
- **Conteinerização:** Isolamento em nível de sistema operacional e padronização de ambiente de runtime gerenciados integralmente via `Docker` e `Docker Compose`.
