FROM python:3.9-slim

WORKDIR /app

# Install git for git dependencies
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Install the package
RUN pip install .

# Expose the port
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "processing_pipeline.api:app", "--host", "0.0.0.0", "--port", "8000"]
