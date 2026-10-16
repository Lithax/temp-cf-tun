FROM nginx:latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl jq ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY proxy.conf /etc/nginx/snippets/mcp-proxy.conf
COPY 40-services.sh /docker-entrypoint.d/40-services.sh

# sed strips Windows CRLFs (the /mnt/c checkout problem)
RUN sed -i 's/\r$//' /docker-entrypoint.d/40-services.sh /etc/nginx/snippets/mcp-proxy.conf \
    && chmod +x /docker-entrypoint.d/40-services.sh \
    && mkdir -p /etc/nginx/generated
