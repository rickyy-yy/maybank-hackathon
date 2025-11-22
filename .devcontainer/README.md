# Dev Container Setup

This directory contains the configuration for a VS Code Dev Container that provides a complete development environment for the Maybank Hackathon project.

## What's Included

- **Python 3.11** with pip and virtual environment support
- **Node.js 18.x** with npm
- **Docker & Docker Compose** for running services (PostgreSQL, Redis)
- **Development tools**: Git, build tools, PostgreSQL client
- **VS Code extensions**: Python, TypeScript, ESLint, Prettier, Tailwind CSS, and more

## Prerequisites

1. **VS Code** with the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) installed
2. **Docker Desktop** (or Docker Engine + Docker Compose) running on your machine

## Getting Started

1. **Open the project in VS Code**
   ```bash
   code .
   ```

2. **Reopen in Container**
   - Press `F1` or `Ctrl+Shift+P` (Windows/Linux) / `Cmd+Shift+P` (Mac)
   - Select: **Dev Containers: Reopen in Container**
   - Wait for the container to build (first time may take a few minutes)

3. **The container will automatically:**
   - Install Python dependencies from `backend/requirements.txt`
   - Install Node.js dependencies from `frontend/package.json`
   - Start PostgreSQL and Redis services via Docker Compose
   - Run database migrations

## Running the Application

Once the container is ready, you can run the backend and frontend:

### Backend (FastAPI)
```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
The API will be available at `http://localhost:8000`

### Frontend (React + Vite)
```bash
cd frontend
npm run dev
```
The frontend will be available at `http://localhost:5173`

## Docker Services

The dev container automatically starts PostgreSQL and Redis using Docker Compose. You can manage them with:

```bash
# View running services
docker-compose ps

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Start services manually
docker-compose up -d postgres redis
```

## Port Forwarding

The following ports are automatically forwarded:
- **8000**: Backend API
- **5173**: Frontend Dev Server
- **5432**: PostgreSQL
- **6379**: Redis

## Environment Variables

The dev container sets these environment variables:
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `PYTHONPATH`: Set to `/workspace/backend`

You can add additional environment variables in `.devcontainer/devcontainer.json` under `remoteEnv`.

## Troubleshooting

### Container won't start
- Ensure Docker Desktop is running
- Check Docker has enough resources allocated (at least 4GB RAM recommended)
- Try rebuilding: `F1` → **Dev Containers: Rebuild Container**

### Database connection issues
- Wait a few seconds after container starts for PostgreSQL to be ready
- Check if services are running: `docker-compose ps`
- View PostgreSQL logs: `docker-compose logs postgres`

### Python/Node dependencies not installing
- Check the post-create script output in the terminal
- Manually run: `cd backend && pip3 install -r requirements.txt`
- Manually run: `cd frontend && npm install`

## Customization

You can customize the dev container by editing:
- `.devcontainer/devcontainer.json`: Main configuration
- `.devcontainer/Dockerfile`: Container image definition
- `.devcontainer/post-create.sh`: Setup script that runs after container creation

## Notes

- The workspace folder (`/workspace`) is automatically mounted from your local machine
- Changes to files are synced in real-time
- The container uses the `vscode` user (non-root) for security
- Python virtual environment is set up in `~/.venv`

