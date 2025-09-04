#!/bin/bash
# Radio Request Tracker - Linux/Mac launcher

echo "Starting Radio Request Tracker v2.0..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Creating..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

# Start the application
python app.py