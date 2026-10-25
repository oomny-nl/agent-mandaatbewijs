# Eén image voor uitgever, inkomensregister, demo en tests. Versies op digest gepind.
FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv

FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f
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
