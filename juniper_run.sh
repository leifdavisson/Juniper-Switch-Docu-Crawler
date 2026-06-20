#!/bin/bash

# Juniper Docu-Crawler Execution Script

echo "Checking dependencies..."
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed. Please install it first."
    exit 1
fi

if [ -f requirements.txt ]; then
    echo "Installing Python dependencies..."
    pip3 install -r requirements.txt
else
    echo "requirements.txt not found. Please ensure dependencies like netmiko and netaddr are installed."
fi

echo "Starting Juniper Docu-Crawler..."
python3 juniper_crawler.py "$@"

echo "Juniper run completed."
