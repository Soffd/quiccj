#!/bin/sh
# Regenerate the self-signed certificate used by the local aioquic interop server.
# The private key is intentionally not committed to the repository.
set -e
cd "$(dirname "$0")"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout key.pem -out cert.pem -days 3650 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
echo "wrote cert.pem and key.pem"
