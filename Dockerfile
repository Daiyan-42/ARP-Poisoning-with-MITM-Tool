FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iputils-ping tcpdump nftables \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY arplab /app/arplab
COPY tests /app/tests
CMD ["python", "-m", "arplab.node", "attacker"]
