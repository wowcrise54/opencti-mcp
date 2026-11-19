FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN test -f src/opencti_mcp/server.py || (echo 'Missing src/opencti_mcp/server.py' >&2; exit 1)
RUN pip install --no-cache-dir .

USER 65532:65532
ENTRYPOINT ["opencti-mcp"]
