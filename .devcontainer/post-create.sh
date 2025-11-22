#!/bin/bash

set -e

# Change to workspace directory
cd /workspace || exit 1

# Set up Python virtual environment (if Python is available)
echo "🐍 Setting up Python virtual environment..."
if command -v python3 &> /dev/null; then
    python3 -m venv ~/.venv 2>/dev/null || true
    if [ -f ~/.venv/bin/activate ]; then
        echo 'source ~/.venv/bin/activate' >> ~/.bashrc
        echo "✅ Python virtual environment created"
    fi
else
    echo "⚠️  Python3 not found, skipping venv setup"
fi

echo "🚀 Setting up development environment..."

# Install Python dependencies
echo "📦 Installing Python dependencies..."
if [ -d "/workspace/backend" ] && [ -f "/workspace/backend/requirements.txt" ]; then
    cd /workspace/backend
    pip3 install --user -r requirements.txt || echo "⚠️  Some Python dependencies may have failed to install"
    echo "✅ Python dependencies installation completed"
else
    echo "⚠️  backend/requirements.txt not found, skipping Python dependencies"
fi

# Install Node.js dependencies
echo "📦 Installing Node.js dependencies..."
if [ -d "/workspace/frontend" ] && [ -f "/workspace/frontend/package.json" ]; then
    cd /workspace/frontend
    npm install || echo "⚠️  Some Node.js dependencies may have failed to install"
    echo "✅ Node.js dependencies installation completed"
else
    echo "⚠️  frontend/package.json not found, skipping Node.js dependencies"
fi

# Wait for PostgreSQL to be ready (if docker-compose is available)
echo "⏳ Checking PostgreSQL connection..."
if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
    timeout=30
    counter=0
    # Try docker compose first (newer), fallback to docker-compose
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    else
        COMPOSE_CMD="docker-compose"
    fi
    
    until $COMPOSE_CMD exec -T postgres pg_isready -U vulnforge > /dev/null 2>&1; do
        if [ $counter -ge $timeout ]; then
            echo "⚠️  PostgreSQL did not become ready in time (services may still be starting)"
            break
        fi
        echo "   Waiting... ($counter/$timeout)"
        sleep 1
        counter=$((counter + 1))
    done
    if [ $counter -lt $timeout ]; then
        echo "✅ PostgreSQL is ready"
    fi
else
    echo "⚠️  docker-compose not available, skipping PostgreSQL check"
fi

# Run database migrations (optional, can be run manually later)
echo "🗄️  Attempting database migrations..."
if [ -d "/workspace/backend" ] && [ -f "/workspace/backend/alembic.ini" ]; then
    cd /workspace/backend
    # Activate venv if it exists, otherwise use system python
    if [ -f ~/.venv/bin/activate ]; then
        source ~/.venv/bin/activate
    fi
    # Wait a bit for services to be ready
    sleep 2
    alembic upgrade head 2>/dev/null || echo "⚠️  Migrations skipped (DB may not be ready yet - run 'alembic upgrade head' manually later)"
    echo "✅ Database migration check completed"
else
    echo "⚠️  backend/alembic.ini not found, skipping migrations"
fi

echo ""
echo "✨ Development environment setup complete!"
echo ""
echo "📝 Quick start commands:"
echo "   Backend:  cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
echo "   Frontend: cd frontend && npm run dev"
echo ""
echo "🐳 Docker services:"
echo "   Start:    docker-compose up -d"
echo "   Stop:     docker-compose down"
echo "   Logs:     docker-compose logs -f"
echo ""

