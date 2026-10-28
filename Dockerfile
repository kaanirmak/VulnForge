FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
WORKDIR /app
COPY pyproject.toml ./
COPY requirements ./requirements
COPY vulnforge ./vulnforge
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements/build.lock -r requirements/runtime.lock \
    && pip install --no-cache-dir --no-deps --no-build-isolation . \
    && useradd --system --uid 10001 vulnforge
RUN mkdir /data && chown vulnforge:vulnforge /data
USER vulnforge
ENV DATABASE_PATH=/data/vulnforge.db
CMD ["uvicorn", "vulnforge.api:app", "--host", "0.0.0.0", "--port", "8000"]
