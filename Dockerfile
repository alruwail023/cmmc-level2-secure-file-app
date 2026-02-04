# Dockerfile for secure_uploader (Flask)
FROM python:3.10-slim

# Create non-root user (good practice)
RUN useradd -m appuser
WORKDIR /app

# Install system dependencies (if needed later you can add more)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
  && rm -rf /var/lib/apt/lists/*

# Copy app code
COPY . /app

# Install Python deps
RUN pip install --no-cache-dir -r requirements.txt

# Flask / gunicorn config
ENV PORT=5000
EXPOSE 5000

# Gunicorn entrypoint – assumes your Flask object is app in main.py
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "main:app"]

