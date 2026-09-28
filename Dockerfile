# Updated on 2026-09-24 against production. Production does NOT run in a
# container -- it is native, in a Python venv under systemd
# (reon-mobile-relay.service) -- and this file is a translation of it.
#
# 3.14, not 3.12: that is production's venv version (Python 3.14.4, checked).
FROM python:3.14-slim

WORKDIR /app

# mysqlclient compiles, so it needs a compiler and headers at build time.
# They stay in the image for now: trimming that needs a two-stage build, and
# there is no way to test that build here without Docker.
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    build-essential \
    pkg-config \
    && pip install --no-cache-dir mysqlclient \
    && rm -rf /var/lib/apt/lists/*

# `config.ini` was removed from this list on purpose, and this is a security
# fix, not tidying. It is the file that holds the MySQL password -- in
# production `[mysql]` is active, with host, user, passwd and db -- and a
# COPY would leave it baked into an image layer, from which it does not come
# back out even by deleting the file afterwards. Mount it as a volume, or
# pass it through the environment.
#
# capture_merge.py is included because it is what joins the two halves of a
# match recorded by tournament mode; without it the recording is useless
# inside the container.
COPY server.py peers.py users.py capture_merge.py ./

# Where tournament mode records to. In production this is created by
# systemd's StateDirectory=reon-captures, which hands over
# /var/lib/reon-captures already owned correctly. Here it has to be created
# by hand -- and this already failed once in production for the opposite
# reason: the directory existed and belonged to another user, so the relay
# could not write to it and silently fell back to the local file.
RUN mkdir -p /var/lib/reon-captures

EXPOSE 31227/tcp

CMD ["python3", "-u", "server.py"]
