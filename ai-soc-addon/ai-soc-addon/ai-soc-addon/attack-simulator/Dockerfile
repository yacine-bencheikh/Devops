FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir requests
ENV PYTHONUNBUFFERED=1
COPY attack.py .
CMD ["python", "attack.py"]
