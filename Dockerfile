FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    build-essential \
    pkg-config \
    && pip install --no-cache-dir mysqlclient \
    && rm -rf /var/lib/apt/lists/*

COPY server.py peers.py users.py config.ini ./

EXPOSE 31227/tcp

CMD ["python3", "-u", "server.py"]
