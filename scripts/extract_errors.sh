#!/bin/zsh
# Extracts system errors/warnings for last 24 hours (writes to project ./logs)

mkdir -p ./logs
/usr/bin/log show --style syslog --last 24h | /usr/bin/grep -Ei "error|fail|warning|denied" > ./logs/errors.log
echo "Saved errors to ./logs/errors.log"
