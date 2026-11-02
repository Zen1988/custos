FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY web ./web
COPY docs ./docs
RUN pip install --no-cache-dir '.[postgres,console]'
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["uvicorn", "custos.console_gateway:create_gateway", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
