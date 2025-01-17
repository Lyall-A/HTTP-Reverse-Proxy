#!/bin/bash
cd "$( dirname "$0" )"

# Keep the process running if it crashes
while true; do
  echo "Updating proxy..."
  npm i -g git@github.com:victornpb/HTTP-Reverse-Proxy.git
  reverseproxy start
  echo "Reverse Proxy crashed. Restarting in 5 seconds..."
  sleep 5
done