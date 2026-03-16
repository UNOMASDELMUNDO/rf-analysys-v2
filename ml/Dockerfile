FROM python:3.11-slim

RUN pip install --no-cache-dir \
    numpy \
    scipy \
    scikit-learn \
    joblib \
    pandas \
    pymongo \
    redis

WORKDIR /app
COPY *.py /app/

CMD ["python3", "ml_engine.py"]
