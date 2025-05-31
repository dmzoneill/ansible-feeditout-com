#!/bin/bash

LOG="/var/log/ansible-pull.log"
TO="{{ email }}"

# Sanitize and send
cat "$LOG" | \
  iconv -f utf-8 -t ascii//TRANSLIT | \
  /usr/bin/mail -a "Content-Type: text/plain; charset=us-ascii" \
                -a "Content-Transfer-Encoding: 7bit" \
                -s "Ansible-pull report from $(hostname)" "$TO"

# Truncate after sending
truncate -s 0 "$LOG"
