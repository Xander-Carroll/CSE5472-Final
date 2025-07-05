# DROP_TABLE_OWLET

## Description
This is a project for the CSE 5472 (Information Security Projects) class. It is a suite of scripts that will run several network based attacks meant to target IoT devices. The scripts will then produce an 'nmap like' output with the results.

This suite is a part of a semester long research project where we looked into the vulnerabilities of typical IoT camera devices. The presentation gives more details about the research and can be found [here](presentations/Final%20Presentation.pdf). Using shodan.io, we found many IoT cameras that were connected to the internet with no password protection. We found many more which are presumed to have simple vulnerabilities that can be found with this script.

## Dependencies
This script requires the following python modules: 
- `python-nmap`

And the following utilities:
- `hydra`

It is recommended that you install the python modules in a virtual environment using `pip`. The following is an example of how you might do this:
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
#       wordlist - a wordlist file to be used for brute force attacks [default=wordlists/example-list.txt].
```

## Wordlists
A wordlist is required for the brute force attacks. The provided wordlist is *very* short. It is a proof of concept that exploits known vulnerabilities. If you are looking to find new vulnerabilities, an external wordlist should be used. Many good wordlists can be found in the [SecList](https://github.com/danielmiessler/SecLists) repository.

Using a longer wordlist may take a considerable amount of time.
