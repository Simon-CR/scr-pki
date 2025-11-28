#!/bin/bash
set -e

# Check if we are in production or development
if [ "$ENVIRONMENT" = "production" ]; then
    echo "Starting in PRODUCTION mode"
    # Run without reload, potentially with multiple workers
    # Using 4 workers as a default for production
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
else
    echo "Starting in DEVELOPMENT mode"
    # Run with reload for development
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
fi
