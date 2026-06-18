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
if [ "$1" == "--retry" ]; then
    if [ -z "$2" ]; then
        echo "Please provide the JSON failure log file to retry. e.g., ./juniper_run.sh --retry juniper_failed_hosts.json"
        exit 1
    fi
    python3 juniper_crawler.py --retry "$2"
elif [ "$1" == "--subnets" ]; then
    if [ -z "$2" ]; then
        echo "Please provide subnets. e.g., ./juniper_run.sh --subnets 192.168.1.0/24"
        exit 1
    fi
    python3 juniper_crawler.py --subnets "$2"
else
    python3 juniper_crawler.py
fi

echo "Juniper run completed."
