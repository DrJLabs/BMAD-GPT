FROM python:3.12-slim

# Copy requirements first for better Docker layer caching
COPY requirements.txt /app/requirements.txt
WORKDIR /app
ENV PYTHONPATH=/app

# Install dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install pytest pytest-asyncio httpx

# Copy application code
COPY app /app
COPY tests /app/tests
COPY pytest.ini /app/pytest.ini

EXPOSE 5555

# Update build time label
LABEL build_time="2025-02-21T12:00:00Z"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5555"]