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

# Copy ALL application files
COPY . .

# List files to debug
RUN ls -la

# Expose port
EXPOSE 10000

# Start the application
CMD ["python", "app.py"]
