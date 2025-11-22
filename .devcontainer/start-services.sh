#!/bin/bash

# Start PostgreSQL and Redis services
cd /workspace || exit 1

if command -v docker &> /dev/null; then
    # Try docker compose (newer) first, fallback to docker-compose
    if docker compose version &> /dev/null 2>&1; then
        docker compose up -d postgres redis 2>&1 || echo "⚠️  Failed to start services with 'docker compose'"
    elif command -v docker-compose &> /dev/null; then
        docker-compose up -d postgres redis 2>&1 || echo "⚠️  Failed to start services with 'docker-compose'"
    else
        echo "⚠️  Docker Compose not available"
    fi
else
    echo "⚠️  Docker not available - make sure Docker Desktop is running"
fi

