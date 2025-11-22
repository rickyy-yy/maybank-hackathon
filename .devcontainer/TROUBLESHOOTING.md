# Dev Container Troubleshooting

## Common Issues and Solutions

### 1. Build Fails with Exit Code 1

**Possible causes:**
- Docker Desktop not running
- Insufficient Docker resources (RAM/CPU)
- Network issues downloading features
- Windows path issues

**Solutions:**
1. **Ensure Docker Desktop is running**
   - Open Docker Desktop
   - Wait for it to fully start (whale icon should be steady)
   - Check Docker Desktop settings → Resources → ensure at least 4GB RAM allocated

2. **Check Docker is accessible**
   ```powershell
   docker --version
   docker ps
   ```

3. **Try rebuilding the container**
   - In VS Code: `F1` → "Dev Containers: Rebuild Container"
   - Or delete the container and rebuild: `F1` → "Dev Containers: Rebuild Container Without Cache"

4. **Check VS Code Dev Containers extension**
   - Ensure the "Dev Containers" extension is installed and up to date
   - Version should be 0.431.1 or newer

5. **Check Windows path length**
   - Windows has a 260 character path limit
   - If your project path is very long, try moving it to a shorter path like `C:\dev\maybank-hackathon`

### 2. Features Not Installing

If the Python/Node.js/Docker features fail to install:

**Solution:** Use the simplified Dockerfile approach (see `devcontainer-simple.json` alternative)

### 3. Docker Compose Not Working

If `docker compose` commands fail inside the container:

**Solution:** 
- Ensure Docker Desktop is running on the host
- The `docker-outside-of-docker` feature should mount the Docker socket
- Try running `docker ps` inside the container to verify Docker access

### 4. Services Won't Start

If PostgreSQL/Redis won't start:

**Solution:**
- Ports 5432 or 6379 might be in use
- Check: `netstat -ano | findstr :5432` (Windows)
- Stop any local PostgreSQL/Redis instances
- Or change ports in `docker-compose.yml`

### 5. Python/Node Not Found

If Python or Node.js commands don't work:

**Solution:**
- The features should install them automatically
- Check: `python3 --version` and `node --version` in container
- If missing, the features may have failed - check build logs

## Getting More Information

1. **View detailed build logs:**
   - Open VS Code Output panel (`Ctrl+Shift+U`)
   - Select "Dev Containers" from the dropdown
   - Look for error messages

2. **Check container logs:**
   ```bash
   docker ps -a
   docker logs <container-id>
   ```

3. **Try manual build:**
   ```bash
   cd .devcontainer
   docker build -f Dockerfile -t devcontainer-test ..
   ```

## Alternative: Use Docker Compose Directly

If the dev container continues to have issues, you can run the services directly:

```bash
# Start services
docker-compose up -d postgres redis

# Then run backend/frontend locally on your machine
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload

# In another terminal
cd frontend
npm install
npm run dev
```

## Still Having Issues?

1. Check the VS Code Dev Containers documentation: https://code.visualstudio.com/docs/devcontainers/containers
2. Check Docker Desktop logs: Docker Desktop → Troubleshoot → View logs
3. Try the simplified configuration (see below)

