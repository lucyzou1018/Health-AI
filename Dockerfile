# syntax=docker/dockerfile:1
FROM python:3.11-slim AS base
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# 安装系统依赖（可按需扩展 slither / anchor 等工具）
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY backend ./backend
COPY skills ./skills
COPY dist ./dist
COPY standalone-agent-audit ./standalone-agent-audit
COPY README.md ./README.md
COPY frontend ./frontend

WORKDIR /app/backend
RUN pip install -r requirements.txt

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
