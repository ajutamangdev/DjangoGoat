FROM python:3.13-alpine3.21

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=core.settings
ENV DEBUG=0

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

RUN apk add --no-cache py3-pip && pip install uv

COPY pyproject.toml .
COPY uv.lock .

RUN python3 -m venv .venv && \
    .venv/bin/pip install --upgrade pip && \
    .venv/bin/pip install uv gunicorn && \
    .venv/bin/uv sync

COPY . .

ENV VIRTUAL_ENV=/app/.venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN uv run python3 manage.py migrate
RUN uv run python manage.py collectstatic --noinput

RUN echo "⚠️  WARNING: This container contains intentional security vulnerabilities for educational purposes only!" > /app/WARNING.txt

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8000

CMD ["uv", "run", "gunicorn", "core.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--chdir", "src"]
