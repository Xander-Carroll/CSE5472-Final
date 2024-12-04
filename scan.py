#!/usr/bin/env python3

#   scan.py [network] [wordlist]
#       network  - the network submask to scan for vulnerable IOT devices [default=192.168.0.0/24].
#       wordlist - a wordlist file to be used for brute force attacks [default=wordlists/example-list.txt].

# The script does the following:
#   1) Scans the network for devices.
#   2) Finds the open ports of the devices that it found.
#   3) Tries to exploit the open ports. If any of the following services are found, an attack will be attempted:
#       - RTSP
#       - FTP
#       - SSH
#   4) Prints the results in a readable, nmap style, table.

# Python Built-In Modules.
import os.path
import sys
import datetime 
import subprocess
import re

# Required Dependency Modules.
import nmap

# Default options if command line arguments are not given.
DEFAULTS = {
    'network': "192.168.0.0/24",
    'wordlist': './wordlists/example-list.txt',
    'rtsp_urls': './wordlists/rtsp_urls.txt',
}

def main():
    # Creating an options dictionary with the proper defaults.
    options = DEFAULTS.copy()
    
    # Use the command line args to set options.
    if(parse_command_line_args(options) != 0):
        return

    # Print the header information for the scan.
    time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("")
    print(f"Starting scan at {time_stamp}")
    print(f"scan report for {options['network']}")

    # Find all the devices with open ports on the network
    open_ports = find_open_ports(options)
    
    # Launch attacks based on the open ports.
    launch_attacks(options, open_ports)

    # Printing the report.
    print_report(open_ports)


def parse_command_line_args(options):
    '''
    Will check the command line args and add them to the options dictionary.
        Returns 0 on success, -1 on invalid number of arguments, and -2 on unfound file.
    '''
    
    # Verifying the number of arguments.
    if(len(sys.argv) > 3):
        print(f"[ERROR]: Usage is \"{sys.argv[0]} [network] [wordlist]\"")
        return -1

    # Setting the wordlist option.
    if(len(sys.argv) > 2):
        options['wordlist'] = sys.argv[2]

    # Setting the network option.
    if(len(sys.argv) > 1):
        options['network'] = sys.argv[1]

    # Check if the wordlist exists.
    if(not os.path.isfile(options['wordlist'])):
        print(f"[WARNING]: wordlist=\"{options['wordlist']}\" was not found.")
        return -2

    # Check if the rtsp_urls exists.
    if(not os.path.isfile(options['rtsp_urls'])):
        print(f"[WARNING]: rtsp_urls=\"{options['rtsp_urls']}\" was not found.")
        return -2

    # Return success.
    return 0

def find_open_ports(options):
    '''
    Returns a map of all the devices on the network with open ports. 
    The key is the ip address, the value is an array of dictionaries.

    The return format is {ipAddr: [{port, service, isVulnerable}, ...], ...}
    '''

    # It is possible to scan for devices and their open ports using one nmap command.
    # To print a progress report, those tasks need to be done seperatley.
    # Because scans can take time, the progress report is nice to have.

    # Finding all devices on the network using a ping scan.
    nm = nmap.PortScanner()
    nm.scan(hosts=options['network'], arguments="-sn -T4")

    # Scan each device for open ports.
    i = 1
    open_ports = {}
    nmdevice = nmap.PortScanner()
    device_count = len(nm.all_hosts())
    for host in nm.all_hosts():
        # Printing a progress report for scanned devices.
        print(f"scanning device {host} | {i}/{device_count}...        \r", end ="")
        i += 1

        # Scanning each device for open ports.
        try:
            nmdevice.scan(hosts=host, arguments="-T4")
            for port in nmdevice[host]['tcp'].keys():
                if nmdevice[host]['tcp'][port]['state'] == 'open':
                    if(host in open_ports):
                        open_ports[host].append({"port":port, "service":nmdevice[host]['tcp'][port]['name'], "isVulnerable":False})
                    else:
                        open_ports[host] = [{"port":port, "service":nmdevice[host]['tcp'][port]['name'], "isVulnerable":False}]
        except:
            continue
    
    return open_ports

def launch_attacks(options, open_ports):
    '''
    Launches the correct attack script based on the open ports and the services that are running on them.

    Will edit the open_ports dictionary with the results of the attack.
    '''

    # Launching attacks based on service
    for device in open_ports:
        for port in open_ports[device]:

            # The hydra based attacks.
            hydra_result = None
            if(port["service"] == 'ssh'):
                hydra_result = subprocess.run(["scripts/ssh_brute.sh", options['wordlist'], device, str(port["port"])], capture_output=True, text=True)
            elif(port["service"] == 'rtsp'):
                hydra_result = subprocess.run(["scripts/rtsp_brute.sh", options['wordlist'], device, str(port["port"]), options["rtsp_urls"]], capture_output=True, text=True)
            elif(port["service"] == 'ftp'):
                hydra_result = subprocess.run(["scripts/ftp_brute.sh", options['wordlist'], device, str(port["port"])], capture_output=True, text=True)
            
            # If hydra was used, analyze the output.
            if (hydra_result != None):
                result = process_hydra_result(hydra_result)
                port["isVulnerable"] = result["wasSuccess"]


def process_hydra_result(result):
    '''
    Given the output from a Hydra process run, will determine success or failure of the attack.

    The result is returned as a dictionary {wasSuccess, usernmame, password}
    '''

    # If a valid username/password was not found, return.
    if(result.returncode != 0):
        return {"wasSuccess":False, "usernmame":None, "password":None}    

    # If a valid username was found, save it.
    login = None
    matchLogin = re.search('login:(.*)', result.stdout)
    if(matchLogin):
        login = matchLogin.group(1).split("password: ")[0]
    
    # If a valid password was found, save it.
    password = None
    matchPass = re.search('password:(.*)', result.stdout)
    if(matchPass):
        password = matchPass.group(1)

    # Return the username/password.
    return {"wasSuccess":True, "usernmame":login, "password":password}

def print_report(open_ports):
    '''
    Prints the result of the attacks in the proper format.
    '''

    for device in open_ports:
        # Print a new-line that clears the progress report if needed.
        print(" "*60)

        # Print the address of the device.
        print(device)

        # Print the column header.
        print("PORT      SERVICE        ATTACK")

        # Print the findings.
        for port in open_ports[device]:
            print(str(port["port"]).ljust(10) + port["service"].ljust(15) + ("VUNERABLE" if port["isVulnerable"] else "-").ljust(11))
    
    # A final newline for spacing.
    print("")



# Run the main function.
if __name__=="__main__":
    main()