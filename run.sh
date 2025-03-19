#!/bin/bash
source venv/bin/activate
source .env
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
