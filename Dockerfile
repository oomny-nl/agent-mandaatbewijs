# Eén image voor uitgever, inkomensregister, demo en tests. Versies op digest gepind.
FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv

FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb
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
