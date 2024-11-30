# DROP_TABLE_owlet

## Dependencies
This script requires the following python modules: 
- `python-nmap`
- `requests`

It is recommended that you install them in a virtual enviornment using `pip`. The following is an example of how you might do this:
```
python -m venv env
source env/bin/activate
pip install python-nmap
pip install requests
```

## Usage
This script takes two optional command line arguments:

```
#   scan.py [network] [wordlist]
#       network  - the network submask to scan for vulnerable IOT devices [default=192.168.0.0/24].
#       wordlist - a wordlist file to be used for brute force attacks [default=wordlists/rockyou.txt].
```

## Wordlists
The default wordlist that will be used for brute force attacks is `rockyou.txt`. It will be downloaded automatically by the script.
This wordlist and many others can be found in the [SecList](https://github.com/danielmiessler/SecLists) repository.