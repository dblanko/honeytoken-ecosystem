# Honeytoken DB canary listener -- minimal image, no external deps
# (fake_postgres_listener.py only uses the Python stdlib).
#
# Build:
#   docker build -t honeytoken-listener .
#
# Run:
#   docker run -d -p 5432:5432 \
#     -e TELEGRAM_BOT_TOKEN=xxxx \
#     -e TELEGRAM_CHAT_ID=xxxx \
#     --name honeytoken-listener \
#     honeytoken-listener
#
# Or with --env-file .env (see .env.example)

FROM python:3.12-slim

WORKDIR /app
COPY fake_postgres_listener.py .

ENV LISTEN_PORT=5432
# Without this, Python buffers stdout when it's not attached to a
# real terminal (which is always the case inside a container), and
# `docker compose logs` shows nothing at all until the buffer fills
# or the process exits. Found this the hard way -- the container was
# healthy and running fine, just silent.
ENV PYTHONUNBUFFERED=1
EXPOSE 5432

# don't run as root
RUN useradd --no-create-home --shell /usr/sbin/nologin canary
USER canary

CMD ["python3", "fake_postgres_listener.py"]
