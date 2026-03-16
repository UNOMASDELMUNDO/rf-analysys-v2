FROM python:3.11-slim
RUN pip install --no-cache-dir pymongo redis requests python-dotenv
WORKDIR /app
COPY *.py /app/
CMD ["python3", "alert_manager.py"]
