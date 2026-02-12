FROM python:3.13-slim

# ---- System setup: msodbcsql18 + unixODBC ----
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl gnupg2 ca-certificates apt-transport-https \
      unixodbc unixodbc-dev \
    && curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /usr/share/keyrings/microsoft-prod.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" \
         > /etc/apt/sources.list.d/microsoft-prod.list \
    && apt-get update && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 \
    && rm -rf /var/lib/apt/lists/*

# ---- Python/env ----
# env vars:
#  KEYVAULT_ENDPOINT="https://dev-kv-cus-common.vault.azure.net"
#  EXPOSE_WRAPPED="true"
#  MCP-TRANSPORT="streamable-http"
#  AZURE_MONITOR="InstrumentationKey=f9bca289-f4b6-41ec-b0e3-e42f82fe99c9;IngestionEndpoint=https://centralus-2.in.applicationinsights.azure.com/;LiveEndpoint=https://centralus.livediagnostics.monitor.azure.com/;ApplicationId=bfbb816d-f17c-4bb9-9524-301f58a3ae2a"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_SYSTEM_PYTHON=1

WORKDIR /app

# Install uv
RUN pip install --no-cache-dir uv

# Copy deps first (better layer caching)
COPY pyproject.toml uv.lock ./

# Build needs unixodbc-dev present (already installed above)
RUN uv pip install --system --no-cache-dir .

# App code
COPY src/ ./src

ENV MCP_TRANSPORT=streamable-http
ENV PORT=8000
EXPOSE 8000

CMD ["python", "src/app.py"]
