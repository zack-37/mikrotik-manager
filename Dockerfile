FROM python:3.11-slim

WORKDIR /app

COPY requirements-web.txt .
RUN pip install --no-cache-dir -r requirements-web.txt

COPY update_awg.py .
COPY web/ web/

EXPOSE 5000

CMD ["python", "web/app.py"]
