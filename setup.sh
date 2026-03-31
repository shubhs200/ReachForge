#!/bin/bash
set -e

# System setup
apt update
apt install -y python3-pip

# Fix libclang version conflict
pip3 uninstall -y libclang || true
pip3 install libclang==14.0.6

# Install Python deps
pip3 install -r requirements.txt