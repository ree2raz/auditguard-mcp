# HF Space Docker deployment for auditguard-mcp
# Real MCP server + real Privacy Filter model (1.5B MoE, 50M active params)
# Cache-optimized: split deps by install frequency

FROM python:3.12-slim

WORKDIR /app

# Install uv via pip (fast, no apt-get needed)
RUN pip install --no-cache-dir uv

# === LAYER 1: Light dependencies (fast, rarely change) ===
# These install quickly, so we cache them separately
RUN uv pip install --system --no-cache \
    "pydantic>=2.0.0" \
    "fastapi>=0.110.0" \
    "uvicorn>=0.29.0" \
    "httpx>=0.27.0" \
    "python-dotenv>=1.0.0" \
    "sqlglot>=23.0.0" \
    "faker>=25.0.0" \
    "sqlalchemy>=2.0.0"

# === LAYER 2: Heavy ML dependencies (slow download, rarely change) ===
# These take minutes to download but rarely update
RUN uv pip install --system --no-cache \
    "transformers>=4.40.0" \
    "torch>=2.0.0" \
    "accelerate>=0.26.0" \
    "mcp[cli]>=1.0.0"

# Copy application code (changes won't bust dep layers)
COPY auditguard_mcp/ ./auditguard_mcp/
COPY scripts/ ./scripts/
COPY web/ ./web/
COPY web_app.py ./

# Create data dir and seed DB at build time
RUN mkdir -p data && python scripts/seed_data.py

# HF Spaces uses port 7860
ENV PORT=7860
ENV HF_HOME=/data/huggingface
ENV TRANSFORMERS_CACHE=/data/huggingface

EXPOSE 7860

# The app will download openai/privacy-filter on first startup (~6GB, cached to /data)
CMD ["uvicorn", "web_app:app", "--host", "0.0.0.0", "--port", "7860", "--log-level", "info"]
