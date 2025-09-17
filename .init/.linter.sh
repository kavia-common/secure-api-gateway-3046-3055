#!/bin/bash
cd /home/kavia/workspace/code-generation/secure-api-gateway-3046-3055/api_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

