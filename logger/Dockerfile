FROM python:3.8

WORKDIR /app
COPY source/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY source/ /app

EXPOSE 8080

CMD ["python3", "logger.py"]