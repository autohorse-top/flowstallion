#!/bin/sh
# FlowStallion image dispatcher: run the first arg as the command, else scheduler.
if [ "$#" -gt 0 ]; then
  exec "$@"
fi
exec scheduler
