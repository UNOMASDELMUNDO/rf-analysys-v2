FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    pymongo \
    redis \
    pydantic \
    python-dotenv \
    httpx

COPY *.py /app/

EXPOSE 8890

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8890"]
