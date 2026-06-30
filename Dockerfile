# Multi-stage build: compile the React frontend, then serve it from FastAPI.
FROM node:22-alpine AS frontend
WORKDIR /fe
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# Python 3.13 so the scanner can capture full unverified certificate chains.
FROM python:3.13-slim AS app
WORKDIR /app
ENV PYTHONUNBUFFERED=1
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY --from=frontend /fe/dist ./static
ENV CERTWATCH_STATIC_DIR=/app/static
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
