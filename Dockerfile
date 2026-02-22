# ============================================
# Auto-VAPT: Multi-stage Docker Build
# ============================================
FROM python:3.11-slim AS base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry==1.8.2 && \
    poetry config virtualenvs.create false

# ============================================
# Dependencies stage
# ============================================
FROM base AS dependencies

WORKDIR /app

# Copy dependency definitions
COPY pyproject.toml poetry.lock* ./

# Install dependencies (no dev deps in production)
RUN poetry install --no-root --no-dev --no-interaction 2>/dev/null || \
    poetry install --no-root --no-interaction

# ============================================
# Application stage
# ============================================
FROM dependencies AS app

# Copy application code
COPY . .

# Install the package itself
RUN poetry install --no-interaction

# Create non-root user
RUN groupadd -r autovapt && \
    useradd -r -g autovapt -d /app -s /sbin/nologin autovapt && \
    mkdir -p /app/reports && \
    chown -R autovapt:autovapt /app

USER autovapt

# Default command
ENTRYPOINT ["auto-vapt"]
CMD ["--help"]

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s \
    CMD auto-vapt --version || exit 1

# Labels
LABEL maintainer="uchiha" \
      description="Auto-VAPT: CI/CD Integrated Vulnerability Assessment Scanner" \
      version="1.0.0"
