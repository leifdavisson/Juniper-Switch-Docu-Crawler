FROM python:3.10-alpine

# Install system dependencies (nmap, openssh, git for library pulls if any)
RUN apk add --no-cache nmap openssh-client git bash

WORKDIR /app

# Copy dependency specifications and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source scripts
COPY juniper_crawler.py juniper_parser.py juniper_report_generator.py oui_lookup.py oui.txt* /app/

# Register executable path
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "juniper_crawler.py"]
