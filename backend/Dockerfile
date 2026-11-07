# ---- stage 1: build the frontend
FROM node:22-alpine AS frontend
WORKDIR /fe
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci || npm install
COPY frontend/ ./
RUN npm run build

# ---- stage 2: backend + built frontend
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY backend/pyproject.toml ./
COPY backend/netcheck ./netcheck
COPY backend/tests ./tests
RUN pip install --no-cache-dir -e ".[test]"
COPY --from=frontend /fe/dist ./netcheck/api/static
# least privilege: the app never runs as root (NFR-04)
RUN useradd --uid 1000 --create-home netcheck && mkdir -p /data/db && chown -R netcheck /data
USER netcheck
CMD ["uvicorn", "netcheck.api.app:app", "--host", "127.0.0.1", "--port", "8001"]
