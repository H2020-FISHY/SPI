FROM python:3-slim as builder
RUN adduser --system --no-create-home nonroot
RUN apt update -y && apt install -y iproute2 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


FROM builder
WORKDIR /usr/src/app
COPY src ./src
COPY --chown=nonroot:root .ssl/tls.key:d1 .ssl/tls.key
COPY --chown=nonroot:root .ssl/tls.crt:d1 .ssl/tls.crt
COPY entrypoint.bash entrypoint.bash

EXPOSE 5000

ENTRYPOINT [ "/usr/src/app/entrypoint.bash"]
