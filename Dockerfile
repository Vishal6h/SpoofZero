FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SPOOFZERO_CASE_DB=/data/spoofzero.sqlite3

WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY . .
RUN addgroup --system spoofzero \
    && adduser --system --ingroup spoofzero --home /app spoofzero \
    && mkdir -p /data \
    && chown -R spoofzero:spoofzero /app /data

USER spoofzero
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3).read()" || exit 1

CMD ["python", "run_spoofzero.py", "--host", "0.0.0.0", "--port", "8501"]
