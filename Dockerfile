FROM python:3.12-slim

WORKDIR /app

COPY phish_Checker.py /app/phish_Checker.py

ENTRYPOINT ["python", "/app/phish_Checker.py"]
