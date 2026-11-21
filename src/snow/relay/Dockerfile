# Minimal, secure container image for self-hosting the SNOW Relay Service
FROM python:3.13-slim

WORKDIR /app

# Non-root user for security
RUN groupadd -r snow && useradd -r -g snow snow

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY src/ /app/src/

ENV PYTHONPATH="/app/src"
ENV SNOW_RELAY_HOST="0.0.0.0"
ENV SNOW_RELAY_PORT="8770"

EXPOSE 8770

USER snow

ENTRYPOINT ["python", "-m", "snow.relay"]
