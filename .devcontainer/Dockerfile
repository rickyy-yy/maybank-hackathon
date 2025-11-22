FROM mcr.microsoft.com/devcontainers/base:ubuntu-22.04

# Install system dependencies
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    postgresql-client \
    curl \
    vim \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# Docker CLI and docker-compose-plugin are installed by docker-outside-of-docker feature
# Python and Node.js are installed by their respective features

# Set working directory
WORKDIR /workspace

# Copy setup scripts into the container
# These will be available even if the workspace mount hasn't completed yet
COPY .devcontainer/post-create.sh /tmp/post-create.sh
COPY .devcontainer/start-services.sh /tmp/start-services.sh
RUN chmod +x /tmp/post-create.sh /tmp/start-services.sh

# Note: Python, Node.js, and Docker are installed by features in devcontainer.json
# This Dockerfile only installs system-level dependencies
# Python venv setup is done in post-create.sh after features are installed

