The localhost certificate and PKCS#8 key are public test-only fixtures.
The self-signed certificate has DNS:localhost, CA:FALSE, and a ten-year
validity from generation on 2026-09-17. Never use this key in deployment.
Tests explicitly trust it for a positive handshake, reject it with production
roots, and reject its hostname when connecting to 127.0.0.1.
