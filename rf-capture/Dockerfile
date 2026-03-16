FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    rtl-sdr \
    hackrf \
    librtlsdr-dev \
    libhackrf-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    numpy \
    scipy \
    pymongo

WORKDIR /app
COPY *.py /app/

CMD ["python3", "rf_capture.py"]
