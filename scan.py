#!/usr/bin/env python3

#   scan.py [network] [wordlist]
#       network  - the network submask to scan for vulnerable IOT camera devices [default=192.168.0.0/24].
#       wordlist - a wordlist file to be used for brute force attacks [default=wordlists/rockyou.txt].


# Python Built-In Modules.
import os.path
import sys
import tarfile
import datetime 

# Required Dependency Modules.
import requests
import nmap

# Constants.
ROCK_YOU_LIST_URL = "https://github.com/danielmiessler/SecLists/raw/refs/heads/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz"
WORDLIST_DIR = "wordlists"

# Default options if command line arguments are not given.
DEFAULTS = {
    'network': "192.168.0.0/24",
    'wordlist': './wordlists/rockyou.txt',
    'hasWordList': True
}

def main():
    # Creating an options dictionary with the proper defaults.
    options = DEFAULTS.copy()
    
    # Use the command line args to set options, and check for errors.
    if(parse_command_line_args(options) != 0):
        return
    
    # Check if the wordlist is valid.
    if(not os.path.isfile(options['wordlist'])):
        print(f"[WARNING]: wordlist=\"{options['wordlist']}\" was not found.")
        options['hasWordList'] = False

    # Print the header information for the scan.
    time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("")
    print(f"Starting scan at {time_stamp}")
    print(f"scan report for {options['network']}")

    # Find all the devices with open ports on the network
    open_ports = find_open_ports(options)
    
    # Launching attacks based on service
    for device in open_ports:
        for port in open_ports[device]:
            if(port[1] == 'ssh'):
                pass #TODO: SSH Attack
            elif(port[1] == 'rtsp'):
                pass #TODO: RTSP Attack
            elif(port[1] == 'ftp'):
                pass #TODO: FTP Attack

    # Printing the report.
    for device in open_ports:
        print(" "*60)
        print(device)
        print("PORT      SERVICE        ATTACK")

        for port in open_ports[device]:
            print(str(port[0]).ljust(10) + port[1].ljust(15) + ("VUNERABLE" if port[2] else "-"))


def parse_command_line_args(options):
    '''
    Will check the command line args and add them to the options dictionary.
        Returns 0 on success, and -1 on invalid arguments
    '''
    
    # Verifying the number of arguments.
    if(len(sys.argv) > 3):
        print(f"[ERROR]: Usage is \"{sys.argv[0]} [network] [wordlist]\"")
        return -1

    # Setting the wordlist option.
    if(len(sys.argv) > 2):
        options['wordlist'] = sys.argv[2]

    # If no wordlist was given, use the default one.
    else:
        if(not os.path.isfile(WORDLIST_DIR + "/rockyou.txt")):
            if (download_default_wordlist() == -2):
                return -1

    # Setting the network option.
    if(len(sys.argv) > 1):
        options['network'] = sys.argv[1]

    # Return success.
    return 0

def download_default_wordlist():
    '''
    Will download and extract the default rockyou.txt wordlist.
        Retuns 0 on success, -1 on user cancel, and -2 on exception.
    '''

    # Prompting the user.
    print(f"\"{WORDLIST_DIR}/rockyou.txt\" not found.")
    response = input("Download rockyou.txt [Y/n]: ")

    # If the user doesn't want the wordlist, return a failure.
    if(response[0] == "n" or response[0] == "N"): 
        return -1

    try:
        # Download the file.
        print( "Downloading...")
        r = requests.get(ROCK_YOU_LIST_URL, allow_redirects=True)
        open(WORDLIST_DIR + "/rockyou.txt.tar.gz", 'wb').write(r.content)

        # Extract the file.
        print("Extracting...")
        file = tarfile.open(WORDLIST_DIR + "/rockyou.txt.tar.gz") 
        file.extractall(WORDLIST_DIR) 
        file.close()

        # Remove the tar.gz file.
        os.remove(WORDLIST_DIR + "/rockyou.txt.tar.gz")

    except:
        # If something went wrong, return a failure.
        print("[ERROR]: Could not download rockyou.txt wordfile.")
        return -2

    # Return success.
    return 0

def find_open_ports(options):
    '''
    Returns a map of all the devices on the network with open ports. 
    The key is the ip address, the value is an array of three-tuples.

    The return format is {ipAddr: [(port, service, isVunerable), ...], ...}
    '''

    # Finding all devices on the network using a ping scan.
    nm = nmap.PortScanner()
    nm.scan(hosts=options['network'], arguments="-sn -T4")

    # Scan each device for open ports.
    i = 1
    device_count = len(nm.all_hosts())

    open_ports = {}
    nmdevice = nmap.PortScanner()
    for host in nm.all_hosts():
        # Printing a progress report for scanned devices.
        print(f"scanning device {host} | {i}/{device_count}...        \r", end ="")
        i += 1

        # Scanning the device for open ports.
        try:
            nmdevice.scan(hosts=host, arguments="-T4")
            for port in nmdevice[host]['tcp'].keys():
                if nmdevice[host]['tcp'][port]['state'] == 'open':
                    if(host in open_ports):
                        open_ports[host].append((port, nmdevice[host]['tcp'][port]['name'], False))
                    else:
                        open_ports[host] = [(port, nmdevice[host]['tcp'][port]['name'], False)]
        except:
            continue
    
    return open_ports

# Run the main function.
if __name__=="__main__":
    main()