FROM python:3.8.12-buster

WORKDIR /app
COPY ./ ./
COPY files files

RUN pip3 install -r requirements.txt

CMD ["python3", "/app/start.py", "POST", "http://127.0.0.1:80", "1", "2", "/app/files/proxies/http.txt", "100", "10"]
