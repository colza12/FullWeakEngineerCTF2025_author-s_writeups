FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git socat build-essential \
 && rm -rf /var/lib/apt/lists/*

RUN curl -L https://foundry.paradigm.xyz | bash \
 && bash -lc "foundryup"
ENV PATH="/root/.foundry/bin:${PATH}"

COPY requirements.txt /root/requirements.txt
RUN pip install --no-cache-dir -r /root/requirements.txt

RUN mkdir -p /ctf /usr/lib/python/eth_sandbox
ENV PYTHONPATH="/usr/lib/python"

COPY eth_sandbox/launcher.py /usr/lib/python/eth_sandbox/launcher.py
COPY deploy/ /ctf/deploy
COPY contracts/ /ctf/contracts
COPY entrypoint.sh /ctf/entrypoint.sh
RUN chmod +x /ctf/entrypoint.sh

RUN bash -lc 'cd /ctf/contracts && forge --version && forge build'

EXPOSE 8545 31337
CMD ["/ctf/entrypoint.sh"]
