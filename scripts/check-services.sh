#!/usr/bin/env sh
set -eu

echo "Checking PostgreSQL..."
docker compose exec -T postgres pg_isready -U agent_inbox -d agent_inbox

echo "Checking Redis..."
docker compose exec -T redis redis-cli ping

echo "All service checks passed."
