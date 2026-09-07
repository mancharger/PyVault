# ============================================================
# STAGE 1: Build do Frontend (Node.js / Vite)
# ============================================================
FROM node:20-alpine AS frontend-builder

WORKDIR /frontend

# Contexto de build é a RAIZ do projeto, então o caminho é frontend/
COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# ============================================================
# STAGE 2: Aplicação Python (FastAPI / Uvicorn)
# ============================================================
FROM python:3.12-slim

WORKDIR /code

# Instala dependências Python
COPY backend/requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

# Copia o código do backend
COPY backend/app /code/app

# Copia os arquivos estáticos gerados pelo Vite (pasta dist)
# para dentro da pasta estática do backend
COPY --from=frontend-builder /frontend/dist /code/app/static

# Roda como usuário não-root para maior segurança
RUN useradd -m vaultuser && chown -R vaultuser:vaultuser /code
USER vaultuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
