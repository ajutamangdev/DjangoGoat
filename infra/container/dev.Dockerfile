FROM python:3.13-alpine3.21

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk add --no-cache py3-pip && pip install uv

COPY pyproject.toml .
COPY uv.lock .

RUN python3 -m venv .venv && \
    .venv/bin/pip install --upgrade pip && \
    .venv/bin/pip install uv && \
    .venv/bin/uv sync

COPY . .

ENV VIRTUAL_ENV=/app/.venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN uv run python3 manage.py migrate
RUN uv run python3 manage.py collectstatic --noinput

EXPOSE 8000

RUN echo "⚠️  WARNING: This container contains intentional security vulnerabilities for educational purposes only!" > /app/WARNING.txt

CMD ["uv", "run", "python3", "manage.py", "runserver", "0.0.0.0:8000"]
