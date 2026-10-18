# Eén image voor uitgever, inkomensregister, demo en tests. Versies op digest gepind.
FROM ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 AS uv

FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml uv.lock .python-version README.md ./
RUN uv sync --frozen --no-install-project --group dev --all-extras
COPY src ./src
COPY tests ./tests
COPY vertrouwenslijst.json ./
RUN uv sync --frozen --group dev --all-extras \
    && useradd --uid 10001 --no-create-home app \
    && mkdir -p /data /data-uitgever /data-verifier \
    && chown app /data /data-uitgever /data-verifier
USER 10001
