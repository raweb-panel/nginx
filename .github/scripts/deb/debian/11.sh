#!/bin/bash
set -e

if [ -z "$UPLOAD_USER" ] || [ -z "$UPLOAD_PASS" ]; then
    echo "Missing UPLOAD_USER or UPLOAD_PASS"
    exit 1
fi
