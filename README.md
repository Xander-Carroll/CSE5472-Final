# DROP_TABLE_owlet

## Dependencies
This script requires the following python modules: 
- `python-nmap`

And the following utilities:
- `hydra`

It is recommended that you install the python modules in a virtual enviornment using `pip`. The following is an example of how you might do this:
```
python -m venv env
source env/bin/activate
pip install python-nmap
```

Hydra can be installed with your package manager:
```
apt install hydra
```

## Usage
This script takes two optional command line arguments:

```
#   scan.py [network] [wordlist]
#       network  - the network submask to scan for vulnerable IOT devices [default=192.168.0.0/24].
#       wordlist - a wordlist file to be used for brute force attacks [default=wordlists/rockyou.txt].
```

## Wordlists
A wordlist is required for the brute force attacks. The provided wordlist is *very* short. It is a proof of concept that exploits known vulnerabilities. If you are looking to find new vunereabilities, an external wordlist should be used. Many good wordlists can be found in the [SecList](https://github.com/danielmiessler/SecLists) repository.

Using a longer wordlist may take a considerable amount of time.