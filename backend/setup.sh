#!/bin/bash

# VulnForge Backend Setup Script

set -e

echo "🚀 Setting up VulnForge Backend..."

# Check Python version
if ! command -v python3.11 &> /dev/null; then
    echo "❌ Python 3.11 is required but not found"
    exit 1
fi

echo "✓ Python 3.11 found"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3.11 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install production dependencies
echo "📦 Installing production dependencies..."
pip install -r requirements.txt

# Install development dependencies (optional)
if [ "$1" == "--dev" ]; then
    echo "📦 Installing development dependencies..."
    pip install -r requirements-dev.txt
fi

# Copy environment file if not exists
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  Please update .env file with your configuration"
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p uploads logs migrations/versions

# Verify installation
echo "✅ Verifying installation..."
python -c "import fastapi; import sqlalchemy; import redis; print('All core packages imported successfully')"

echo "
✨ Setup complete! ✨

Next steps:
1. Update the .env file with your configuration
2. Start PostgreSQL and Redis (or use Docker Compose)
3. Run database migrations: alembic upgrade head
4. Load sample data: python scripts/load_templates.py
5. Start the server: uvicorn app.main:app --reload

For development:
  source venv/bin/activate
  uvicorn app.main:app --reload

For production:
  gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker
"