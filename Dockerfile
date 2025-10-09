FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose port
EXPOSE 10000

# Fixed: Use --chdir to set working directory for gunicorn
CMD ["gunicorn", "--chdir", "/app", "app:app", "--bind", "0.0.0.0:10000", "--workers", "2", "--timeout", "120"]
