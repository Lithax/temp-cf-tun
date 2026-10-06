#!/bin/bash

# 1. Sanity check: Ensure cloudflared actually works
if ! cloudflared --version > /dev/null 2>&1; then
    echo "CRITICAL ERROR: cloudflared binary failed to execute."
    exit 1
fi

# 2. Check if SERVICE_URL is provided
if [ -z "$SERVICE_URL" ]; then
    echo "CRITICAL ERROR: SERVICE_URL is empty! Check your compose.yml / .env"
    exit 1
fi

# Clear any old log file
rm -f tunnel.log

# 3. BACKGROUND THREAD: Wait for URL and push to KV
# Wrapping this in ( ... ) & executes this entire block in a separate thread!
(
    echo "Waiting for TryCloudflare URL to be generated..."
    for i in {1..15}; do
        # Make sure the log file exists before trying to grep it
        if [ -f tunnel.log ]; then
            TUNNEL_URL=$(grep -o 'https://[a-zA-Z0-9-]*\.trycloudflare\.com' tunnel.log | head -n 1)

            if [ -n "$TUNNEL_URL" ]; then
                echo "Got URL: $TUNNEL_URL"

                # Push to Cloudflare KV
                curl -s -X PUT "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/storage/kv/namespaces/$NAMESPACE_ID/values/CF_TUNNEL_REDIRECT" \
                     -H "Authorization: Bearer $API_TOKEN" \
                     -H "Content-Type: text/plain" \
                     --data "$TUNNEL_URL"

                echo -e "\nWorker KV Updated! Traffic is now proxying to $TUNNEL_URL"
                
                # Exit ONLY the background thread, leaving cloudflared running
                exit 0
            fi
        fi
        sleep 2
    done

    echo "FAILED to get Tunnel URL. The background thread is giving up."
) &
# ^^^ The '&' above puts everything in the parenthesis into the background.

# 4. FOREGROUND: Start cloudflared
# We use 'tee' so that the logs are written to 'tunnel.log' for the background 
# thread to read, BUT they are also printed to the console so `docker logs` works!
echo "Starting cloudflared targeting $SERVICE_URL..."

cloudflared tunnel --url "$SERVICE_URL" \
	--protocol http2 \
        --no-tls-verify \
	 --no-autoupdate \
        --http-host-header "$HTTP_HOST_HEADER" 2>&1 | tee tunnel.log # remove htp host header if not needed
