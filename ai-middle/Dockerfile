FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./

RUN mkdir -p /sec/ai-middle/logs

ENV PYTHONUNBUFFERED=1

CMD ["python", "log_watcher.py"]