FROM python:3.10-slim

WORKDIR /app

# Ensure logs directory
RUN mkdir logs

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Train the mock model to generate models
RUN python train_pipeline.py

# Expose port
EXPOSE 8000

# Start FastAPI
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
