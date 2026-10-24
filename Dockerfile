FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY vulnforge ./vulnforge
RUN pip install --no-cache-dir . && useradd --system --uid 10001 vulnforge
RUN mkdir /data && chown vulnforge:vulnforge /data
USER vulnforge
ENV DATABASE_PATH=/data/vulnforge.db
CMD ["uvicorn", "vulnforge.api:app", "--host", "0.0.0.0", "--port", "8000"]
