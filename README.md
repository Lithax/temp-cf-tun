Requires a cloudflare worker with designated subdomain e.g. myworker.user.workers.dev with a KV storage & namespace with secret


if you just want a reverse proxy tunnel use basic, if you want automatic auth and routing for specific http services, use advanced-services

btw create symlinks for your .env if you want to use both, so you dont have to copy the .env