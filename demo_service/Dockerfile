FROM python:3.14-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn prometheus-client

COPY app /app/app
COPY traffic_generator.py /app/traffic_generator.py

EXPOSE 8001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]

