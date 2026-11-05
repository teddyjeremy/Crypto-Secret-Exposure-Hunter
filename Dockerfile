FROM golang:1.23-alpine AS gitleaks-build
RUN go install github.com/zricethezav/gitleaks/v8@v8.24.2

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=gitleaks-build /go/bin/gitleaks /usr/local/bin/gitleaks
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 10000
CMD ["python", "scanner/worker.py"]
