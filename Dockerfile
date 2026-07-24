FROM python:3.11.9-slim

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iputils-ping \
    net-tools \
    coreutils \
    && rm -rf /var/lib/apt/lists/*

# Install common testing libraries for Python attacks and regression suites
RUN pip install --no-cache-dir \
    requests \
    urllib3 \
    beautifulsoup4 \
    pytest \
    pydantic

# Create non-root user (matches uid=1000 in your sandbox python code)
RUN useradd -m -u 1000 aegisuser
USER aegisuser
WORKDIR /tmp