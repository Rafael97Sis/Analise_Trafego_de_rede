FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DB_PATH=/data/traffic.db

# libpcap: necessária para compilar filtros BPF (opção -f).
# tcpdump: utilitário útil para depuração dentro do container.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependências primeiro: aproveita o cache de camadas do Docker.
COPY requirements.txt requirements-dev.txt ./
ARG INSTALL_DEV=false
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "$INSTALL_DEV" = "true" ]; then pip install --no-cache-dir -r requirements-dev.txt; fi

COPY app ./app
COPY tests ./tests

VOLUME ["/data"]

# Captura em raw socket exige root ou CAP_NET_RAW (concedida no compose).
ENTRYPOINT ["python", "-m", "app.main"]
CMD ["--help"]
