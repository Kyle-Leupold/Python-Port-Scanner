"""
AUTHOR:         Kyle Leupold
DATE:           2/9/22
DESCRIPTION:    Calculates a range of IPs, scans a list of ports, determines if their open/closed, grabs port banners if available
"""

import ipaddress as ip
import socket, subprocess, csv, os

# [-- FUNCTIONS --] #
def scanPort(target, port): # function, takes in a target IP and a port. returns a list containing details such as the port status and service running

    try:
        return_list = [str(target), port] # the list that will be returned, adds the target and port in [0] and [1]

        # generate a socket to use
        # AF_INET refers to the IPv4 address-family - compared to the AF_INET6 which is the IPv6 address-family
        # SOCK_STREAM means connection-oriented TCP protocol
        a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        a_socket.settimeout(0.5) # timeout (in sec) the socket will wait for a response
        
        check = a_socket.connect_ex((str(target), int(port))) # Connect to a remote socket at address - needs a IP/hostname and a port
                                             # The error indicator is 0 if the operation succeeded, otherwise the value of the errno variable
        if check == 0: # operation succeeded; we connected to address:port
            try:
                service = a_socket.recv(1024).decode() # receive data from the socket, and then decode the data - if no data is received, error is raised
                return_list.append("OPEN") # we know the port is open
                return_list.append(service) # add the decoded service information to the return list
            except: # if an error is raised when trying to receive data, we know the port is open but we cant get the service information
                return_list.append("OPEN")
        else: # if all else fails, we know the port is closed
            return_list.append("CLOSED")

        a_socket.close() # close the socket.. very important
        return return_list # return the list of details
    except:
        return 1

def ping(host):
    interval = 0.2 # time in seconds to wait between the sending of packets NOTE: anything lower than 0.2 requires admin/root privileges
    count = 1 # number of packets to be sent
    wait = 500 # time in milliseconds the script will wait to receive a response before moving on
    countarg = "-c" if os.name == "posix" else "-n"
    
    command = (f"ping -i {interval} {countarg} {count} -W {wait} {host}") # the command we will be running

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
    temp_list = [] # temporary list to store all of the IPs generated
    if len(list) > 2 : return 1 # there are more than two IPs in the argument list
    if int(list[0]) > int(list[1]) : list[0], list[1] = list[1], list[0] # if the 1st IP in the list is larger than the 2nd, switch them
    temp_list.append(list[0]) # append the first IP to the temporary list or else it wont be returned with the rest of the IPs in range

    start = int(list[0] + 1) # convert start IP to int, already in list so add 1 to get the literal first IP
    end = int(list[1]) # convert end IP to int
    hostsBetween = (end - start) # determine how many hosts are inbetween by subtracting the IPs in int form
    print(f"Generated {hostsBetween} IPs between {ip_list[0]} and {ip_list[1]}\n")

    for x in range(start, end): # for every number between the start and end ints
        IpObject = ip.ip_address(x) # generate an IP object of the number
        temp_list.append(IpObject) # append the IP object to the temporary list

    temp_list.append(list[1]) # append the end IP just like we appended the start IP at the beginning
    return temp_list # return the temporary list full of IPs from a range

def checkValidIP(ipString):
    valid = 0 # 0 - invalid, 1 - IP object, 2 - Network object
    try:
        ip.ip_address(ipString) # try to convert a string into an ip object, will error if it is not able to convert it
        valid = 1 # IP is valid
    except ValueError: # IP Object conversion failed. Is it a CIDR format IP that can be turned into a network object?
        try:
            ip.ip_network(ipString) # try to convert the string into a network object.
            valid = 2 # didnt error so we can confirm it is a valid CIDR format IP address
        except ValueError: # string cannot be an IP, nor is it a CIDR IP
            pass # pass - valid is already 0, doesn't matter what we do here
    return valid

def writeTextHeader(ip, fileName): # write the IP header line to a txt file
    with open(fileName+".txt", 'a') as file1: # open the file in append mode so we dont overwrite anything else
        file1.write("-" * 10) # pretty divider ----------
        file1.write(f"\nIP\t{ip}\n") # write the IP header

    return 0

def writeToFile(list, fileName, format): # write to a file (0 = text, 1 = csv)
    if format == 0: # if writing to a txt file
        with open(fileName+".txt", 'a') as file1: # open the file as file1
            file1.write(f"\nPORT\t{list[1]}\n") # write the port number
            file1.write(f"STATUS\t{list[2]}\n") # write the port status
            if len(list) == 4 and list[3] != "": # if we received a service message
                file1.write(f"SERVICE\t{list[3]}") # write the service message received
    elif format == 1: # if writing to a csv file
        with open(fileName+".csv", 'a', newline='') as csv1: # opent eh csv file as csv1
            writeObject = csv.writer(csv1) # create a csv writer object
            writeObject.writerow(list) # write the entire row given by the list passed to the function
    
    return 0

# [-- MAIN --] #
if __name__ == "__main__":
    # VARIABLES
    ip_list = [] # holds all of the IP objects
    alive_hosts = [] # holds all alive hosts
    dead_hosts = [] # holds all dead hosts
    port_list = [] # holds all of the ports
    export_format = 0 # determines what export method to use (0 = txt, 1 = csv)
    export_filename = "testing" # the name of the export file
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
            temp_port_input = input("Enter the ports to be scanned seperated by a space: ").strip() # ask the user for ports, remove extra whitespaces
            result = all(x.isspace() or x.isnumeric() for x in temp_port_input) # confirm every character is either a space or number
            if not result: # if there is something besides a space or number
                print("Invalid input detected - only use numbers and spaces\n") # let the user know
                continue # continue the loop, reprompt the user
            else: # else, all of the characters are either spaces or numbers
                port_list = temp_port_input.split(" ") # split the response by spaces and store them in port_list
                break # break from the loop - we got what we needed

        except ValueError: # if something goes wrong
            print("Invalid Data")

    while True:
        try:
            #ask user if they want to scan hosts that are marked as down
            portScanDeadHosts = input("Do you want to scan ports on 'dead' hosts? (0/blank = No, 1 = Yes): ").strip()
            if "1" in portScanDeadHosts: # if user answered with a 1
                portScanDeadHosts = True # yes
            elif "" == portScanDeadHosts or "0" == portScanDeadHosts: # if user answered with a 0 or left it blank
                portScanDeadHosts = False # no
            else: # if the user put something besides a 1 or 0
                continue # reask the question

            print(f"{'Not scanning' if not portScanDeadHosts else 'Scanning'} dead hosts\n") # confirm the users answer
            break # break from the loop
        except ValueError: # if something goes wrong
            print("invalid input")

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
                
                with open(export_filename+".csv", 'a', newline='') as csv1:
                    writeObject = csv.writer(csv1)
                    writeObject.writerow(["IP", "PORT", "STATUS", "SERVICE"])
                break # step out of the loop
            else:
                continue # continue the loop - reprompt the question
        except ValueError:
            print("Invalid input")

    # END COLLECTION OF USER INPUT

    # We now have all the IPs needed - time to ping each one
    for host in ip_list: # for every entry in ip_list
        alive = ping(host) # ping the host to determine if their alive
        if alive : # if they are alive
            print(f"{host} \tUP") # print up
            alive_hosts.append(host) # append the host to the alive list
        else : # if the host is not alive
            print(f"{host} \tDOWN") # print down
            dead_hosts.append(host) # append the host the dead_hosts list

    if (len(port_list) < 1) or port_list[0] == "": # if no ports were given
        print("\nNo ports were given to scan") # let the user know
    else: # else, there were ports given
        print("-"*10) # print a pretty divider

        if not portScanDeadHosts: # if we are not scanning dead hosts
            for ip in range(len(alive_hosts)): # for every alive host
                print(f"\nScanning {alive_hosts[ip]}") # let the user know what IP were scanning
                
                if export_format == 0: writeTextHeader(str(alive_hosts[ip]), export_filename) # if the user choose .txt, write the text header

                for port in range(len(port_list)): # for each port in the list
                    portScanDetails = scanPort(alive_hosts[ip], port_list[port]) # attempt to connect to each port given on each IP address
                    if portScanDetails == 1: # if this is a one, something went wrong
                        print(f"Something went wrong when scanning {alive_hosts[ip]}:{port_list[port]}")
                        break

                    writeToFile(portScanDetails, export_filename, export_format) # write to either the .csv or .txt

                    for n in range(1, len(portScanDetails)): # go through the details list returned from scanPort(), but skip [0] bc it is the IP
                        print(f"{portScanDetails[n].strip()}\t", end="", flush=True) # print the specific detail which has been stripped of whitespace
                    print() # must be done to make a new line after the details are printed 1 at a time single-line
       
        else: # we are scanning dead ports
            for ip in range(len(ip_list)): # for every IP in the list
                print(f"\nScanning {ip_list[ip]}") # let the user know what IP is being scanned
                if export_format == 0: writeTextHeader(str(ip_list[ip]), export_filename) # if the user choose .txt, write the text header

                for port in range(len(port_list)): # for every port in the list
                    portScanDetails = scanPort(ip_list[ip], port_list[port]) # try and connect to the port
                    if portScanDetails == 1: # if its 1, something went wrong
                        print(f"Something went wrong when scanning {ip_list[ip]}:{port_list[port]}") # let the user know. It will continue to try the next port

                    writeToFile(portScanDetails, export_filename, export_format) # write to the .txt or .csv file

                    for n in range(1, len(portScanDetails)): # for every list item returned from portScan()
                        print(f"{portScanDetails[n].strip()}\t", end="", flush=True) # print the item stripped of whitespace
                    print() # must be done to make a new line after the details are printed 1 at a time on a single-line
        
        print("-"*10) # a divider
    input()






























































#   "YAHAHA, you found me!"
