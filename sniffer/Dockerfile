FROM python:3.11-slim

RUN apt-get update && apt-get install -y tcpdump && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy pymongo redis numpy scipy scikit-learn joblib

WORKDIR /app
COPY *.py /app/

CMD ["python3", "sniffer.py"]
