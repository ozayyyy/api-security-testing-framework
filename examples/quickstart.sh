#!/bin/bash
# Quickstart: start the lab, scan the vulnerable variant, then the secure one.
# Run from the repository root. Lab listens on 127.0.0.1:8001 only.
set -e
.venv/bin/uvicorn lab.app:app --host 127.0.0.1 --port 8001 &
LAB_PID=$!
trap 'kill $LAB_PID' EXIT
sleep 2
.venv/bin/apistf --target http://127.0.0.1:8001 --prefix /vuln --spec examples/openapi-lab.yaml --report findings-vuln.json
curl -s -X POST http://127.0.0.1:8001/_lab/reset > /dev/null
.venv/bin/apistf --target http://127.0.0.1:8001 --prefix /secure --spec examples/openapi-lab.yaml --report findings-secure.json
