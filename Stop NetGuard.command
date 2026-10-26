#!/usr/bin/env bash
# Double-click this file in Finder to stop NetGuard AI.
cd "$(dirname "$0")" || exit 1
./stop.sh
printf '\n'
read -n 1 -s -r -p "Press any key to close..."
printf '\n'
