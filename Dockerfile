FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y bash curl grep ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=cloudflare/cloudflared:latest /usr/local/bin/cloudflared /usr/local/bin/cloudflared

WORKDIR /
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
