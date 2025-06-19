

# Use a slim Python 3.12 base image for smaller size
FROM python:3.12-slim

# Set a common base directory for the monorepo contents
WORKDIR /app

# Install uv
RUN pip install uv


# Create a virtual environment
# RUN uv venv

COPY ./ ./


# Sync dependencies
RUN uv sync --frozen

# Expose the port the app runs on
EXPOSE 8000

# Run the application
CMD ["uv", "run", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
