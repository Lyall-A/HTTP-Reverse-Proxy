#!/bin/bash
cd "$( dirname "$0" )"
while true
do
  reverseproxy start
  
  echo "Restarting in 5 seconds..."
  sleep 5
done