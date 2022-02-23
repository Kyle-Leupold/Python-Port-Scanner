"""
AUTHOR:         Kyle Leupold
DATE:           2/9/22
DESCRIPTION:    Calculates a range of IPs, scans for open ports, grabs port banners
"""

import ipaddress as ip
import socket, subprocess, csv

# [-- FUNCTIONS --] #
def port_scanner(target, port):
    try:
        return_list = [str(target), port]
        a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        a_socket.settimeout(0.5)
        location = (str(target), int(port))
        
        check = a_socket.connect_ex(location)

        if check == 0:
            try:
                service = a_socket.recv(1024).decode()
                return_list.append("OPEN")
                return_list.append(service)
            except:
                return_list.append("OPEN")
        else:
            return_list.append("CLOSED")

        a_socket.close()
        return return_list
    except:
        return 1

def ping(host):
    interval = 0.2 # time in seconds to wait between the sending of packets NOTE: anything lower than 0.2 requires admin/root privileges
    count = 1 # number of packets to be sent
    wait = 500 # time in milliseconds the script will wait to receive a response before moving on
    
    command = (f"ping -i {interval} -c {count} -W {wait} {host}") # the command we will be running

    process = subprocess.Popen(command, shell=True, universal_newlines=True, stdout=subprocess.PIPE)
    out, err = process.communicate()

    if "1 packets received" in out : # if the given string is inside of the output then the host is alive/responded to the ICMP packet
        return True
    else : # then the given string was NOT in the output, we can assume host is down
        return False

def getIpObject(ipString): # convert a string to an IP object
    try: # try it so we can catch errors
        return(ip.ip_address(ipString)) # return a IP object
        
    except ValueError: # if we cant convert the string to an IP object, a ValueError will be raised
        print(f"Something went wrong converting {ipString} into an IP Address object.") # let the user know
        return 1 # return 1.. for 1 error

def getNetworkObject(ipString): # identical to getIpObject, except we're taking in a CIDR notation string and returning a network object
    try: # try it so we can catch errors
        return(ip.ip_network(ipString)) # return a network object
    except ValueError: # if we cant convert the string to a network object, a ValueError will be raised
        print(f"Something went wrong converting {ipString} into a network object.")
        return 1 # return 1.. for 1 error

def getRange(list):  #   get a list of IP addresses between two different IPs
    temp_list = []
    if len(list) > 2 : print("Couldnt compute a range, there were more than 2 items in the list")
    if int(list[0]) > int(list[1]) : list[0], list[1] = list[1], list[0]
    temp_list.append(list[0])

    start = int(list[0] + 1)
    end = int(list[1])
    hostsBetween = (end - start)

    print(f"Generated {hostsBetween} IPs between {ip_list[0]} and {ip_list[1]}\n")

    for x in range(start, end):
        IpObject = ip.ip_address(x)
        temp_list.append(IpObject)

    temp_list.append(list[1])
    return temp_list

def checkValidIP(ipString):
    valid = 0 # 0 - invalid, 1 - IP object, 2 - Network object
    try:
        ip.ip_address(ipString)
        valid = 1
    except ValueError:
        try:
            ip.ip_network(ipString)
            valid = 2
        except ValueError:
            pass
    return valid

def writeIPtoFile(ip, fileName):
    with open(fileName, 'a') as file1:
        file1.write("-" * 10)
        file1.write(f"\nIP\t{ip}\n")


def writeToFile(list, fileName):
    with open(fileName, 'a') as file1:
        file1.write(f"\nPORT\t{list[1]}\n")
        file1.write(f"STATUS\t{list[2]}\n")
        if len(list) == 4 and list[3] != "":
            file1.write(f"SERVICE\t{list[3]}")

# [-- MAIN --] #
if __name__ == "__main__":
    # VARIABLES
    ip_list = [] # holds all of the IP objects
    alive_hosts = [] # holds all alive hosts
    dead_hosts = [] # holds all dead hosts
    port_list = [] # holds all of the ports
    cidr_notation = False # determines whether or not CIDR notation is used - defaults to false
    export_format = 0 # determines what export method to use (0 = txt, 1 = csv)
    export_filename = "testing"
    # END VARIABLES

    # COLLECTION AND VALIDATION OF USER INPUT
    # IP address range / CIDR format IP
    while True:
        try:
            ip_input = input("Enter an IP address in CIDR notation, or the IP at the beginning of the range: ").strip() # ask user for input
            inputValidation = checkValidIP(ip_input) # check if given string is a valid IP, or IP in CIDR notation

            # IP is NOT valid
            if inputValidation == 0:
                print(f"{ip_input} is not a valid IP address, or IP address in CIDR format")
                continue # continue the loop - re-ask the question
            
            # IP is in CIDR notation
            elif inputValidation == 2: # IP is valid and using CIDR notation
                print(f"{ip_input} is a valid IP address in CIDR format")
                ip_list = list(getNetworkObject(ip_input).hosts()) # add all host IP objects from the network to ip_list

            # IP is valid, NOT in CIDR notation
            elif inputValidation == 1: # IP is valid
                ip_list.append(getIpObject(ip_input)) # append the IP object to the ip_list for further use
                
                # get the second (ending) IP
                while True: # endless loop to continuously ask for input
                    try: # try in case there is an error
                        ip_input = input("Enter the IP address at the end of the range: ").strip() # ask the user for input, strip whitespaces before & after
                        inputValidation = checkValidIP(ip_input) # check if the given string is a valid IP or IP in CIDR notation

                        # IP is NOT valid, or it is in CIDR notation
                        if inputValidation != 1:
                            print(f"{ip_input} is not a valid IP address, or it is in CIDR notation") # let the user know
                            continue # continue the loop - reprompt the question
                        
                        # IP is valid
                        else:
                            ip_obj = getIpObject(ip_input) # convert IP to IP object
                            
                            # if the given (end) IP comes before the first IP
                            if int(ip_obj) < int(ip_list[0]): 
                                print(f"Error: {ip_input} comes before {str(ip_list[0])}") # let the user know
                                continue # continue the loop; reprompt the question
                            
                            # if the given (end) IP is the same as the first IP
                            elif int(ip_obj) == int(ip_list[0]):
                                print(f"Error: {ip_input} is the same as {str(ip_list[0])}") # let the user know
                                continue # continue the loop; reprompt the question
                            
                            # ip is now confirmed as a valid input
                            ip_list.append(ip_obj) # append the IP object to the ip_list for further use
                            # generate the IPs between the start and end, and place them inside of ip_list
                            ip_list = getRange(ip_list)
                            
                            break # leave the endless while loop
                    except ValueError: # handle exceptions when prompting for a second IP address
                        print("Invalid Input")
            break # leave the endless while loop - succesfully retrieved a single IP address in CIDR notation, or two IP addresses making a range
        except ValueError: # handle exceptions when prompting for a valid start IP, or an IP in CIDR notation
            print("Invalid Input")

    # Ports to be scanned
    while True:
        try:
            temp_port_input = input("Enter the ports to be scanned seperated by a space: ").strip()
            result = all(x.isspace() or x.isnumeric() for x in temp_port_input)
            if not result:
                print("Invalid input detected - only use numbers and spaces\n") 
                continue
            else:
                port_list = temp_port_input.split(" ")
                break

        except ValueError:
            print("Invalid Data")

    while True:
        try:
            portScanDeadHosts = input("Enter \"y\" if you want to scan ports on 'dead' hosts - leave blank if you only want to scan ports on 'alive' hosts: ").strip()
            if "y" in portScanDeadHosts or "Y" in portScanDeadHosts:
                portScanDeadHosts = True
            elif "" == portScanDeadHosts:
                portScanDeadHosts = False
            else:
                continue

            print(f"{'Not scanning' if not portScanDeadHosts else 'Scanning'} dead hosts\n")
            break
        except ValueError:
            pass

    while True:
        try:
            export_format = input("Enter your prefered export format (default/blank = .TXT, 1 = .CSV): ").strip()
            if export_format == "":
                export_format = 0 # user choose .TXT
                print("Will export in .TXT format\n")
                break # step out of the loop
            elif export_format == "1":
                export_format = 1 # user choose .CSV
                print("Will export in .CSV format\n")
                break # step out of the loop
            else:
                continue # continue the loop - reprompt the question
        except ValueError:
            print("Invalid input")

    # END COLLECTION OF USER INPUT

    # We now have all the IPs needed - time to ping each one
    for host in ip_list:
        alive = ping(host)
        if alive : 
            print(f"{host} \tUP")
            alive_hosts.append(host)
        else : 
            print(f"{host} \tDOWN")
            dead_hosts.append(host)

    # Seperate ports by spaces and store them in list
    if (len(port_list) < 1) or port_list[0] == "": 
        print("\nNo ports were given to scan")

    else:
        print("-"*10)
        if not portScanDeadHosts:
            for i in range(len(alive_hosts)):
                print(f"\nScanning {alive_hosts[i]}")
                writeIPtoFile(str(alive_hosts[i]), 'test.txt')

                for x in range(len(port_list)):
                    portReturnList = port_scanner(alive_hosts[i], port_list[x])
                    writeToFile(portReturnList, 'test.txt')
                    for n in range(1, len(portReturnList)):
                        print(f"{portReturnList[n].strip()}\t", end="", flush=True)
                    print()
        else:
            for i in range(len(ip_list)):
                print(f"\nScanning {ip_list[i]}")
                writeIPtoFile(str(ip_list[i]), 'test.txt')

                for x in range(len(port_list)):
                    portReturnList = port_scanner(ip_list[i], port_list[x])
                    writeToFile(portReturnList, 'test.txt')

                    for n in range(1, len(portReturnList)):
                        print(f"{portReturnList[n].strip()}\t", end="", flush=True)
                    print()
        print("-"*10)
    
#   "YAHAHA, you found me!"