#!/usr/bin/env bash

[[ -f /.dockerenv || ! -z $VIRTUAL_ENV ]] || { echo "[ERROR] You want to be installing this in a virtual environment. Did you call this script standalone?"; exit 1; }

# 1. install fuzzware (excluding angr)
echo "[*] Installing pipeline..."
pip3 install -U -r requirements.txt || exit 1
pip3 install -e . || exit 1

exit 0