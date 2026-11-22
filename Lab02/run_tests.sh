#!/usr/bin/env bash
# Usage: ./run_tests.sh [unit|static|all]     (default: all)
# unit   = the Python services, against an in-memory mock of AWS (no network, no cost)
# static = reads the Terraform files and checks the free tier and security rules (no AWS, no Terraform needed)
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONDONTWRITEBYTECODE=1          # keep __pycache__ out of app/, which Terraform zips and uploads
if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements-dev.txt
fi
case "${1:-all}" in
  unit)   .venv/bin/python -m pytest tests/unit -p no:cacheprovider ;;
  static) .venv/bin/python -m pytest tests/static -p no:cacheprovider ;;
  all)    .venv/bin/python -m pytest -p no:cacheprovider ;;
  *)      echo "usage: $0 [unit|static|all]"; exit 2 ;;
esac
