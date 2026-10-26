#!/usr/bin/env bash
# Double-click this file in Finder to start NetGuard AI.
cd "$(dirname "$0")" || exit 1
./start.sh
status=$?
printf '\n'
if [ "$status" -eq 0 ]; then
  printf 'NetGuard AI is running in the background. You can close this window.\n'
else
  printf 'Startup failed. Read the messages above, then press any key to close.\n'
fi
read -n 1 -s -r -p "Press any key to close..."
printf '\n'
