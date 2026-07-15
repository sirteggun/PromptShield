# PromptShield Enterprise API
FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PROMPTSHIELD_ENV=production \
    PIP_NO_CACHE_DIR=1

# System deps for healthcheck
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY plugins ./plugins
COPY config ./config

RUN pip install --upgrade pip \
    && pip install .

EXPOSE 8000

# API keys must be provided at runtime via PROMPTSHIELD_API_KEY
CMD ["uvicorn", "promptshield.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
