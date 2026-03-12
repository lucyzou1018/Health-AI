# syntax=docker/dockerfile:1
FROM python:3.11-slim AS base
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 安装 Foundry
RUN curl -L https://foundry.paradigm.xyz | bash && \
    export PATH="$HOME/.foundry/bin:$PATH" && \
    foundryup
ENV PATH="/root/.foundry/bin:${PATH}"

# 安装 Python 依赖（包括 Slither）
RUN pip install slither-analyzer

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
