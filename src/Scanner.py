#!/usr/bin/env python3
import networkscan
import psutil
from tabulate import tabulate
import ipaddress
from sys import exit

# Defining Colour Schemas
NONE='\033[00m'
BLACK='\033[01;30m'
RED='\033[01;31m'
GREEN='\033[01;32m'
YELLOW='\033[01;33m'
BLUE='\033[0;34m'
PURPLE='\033[01;35m'
CYAN='\033[01;36m'
WHITE='\033[01;37m'
BOLD='\033[1m'
BLINK='\033[5m'
UNDERLINE='\033[4m'

#Check Valid IP
def checkIP(ip):
    try:
        if ip=="":
            raise ValueError("This Field Cannot Be Empty")
        return ipaddress.ip_address(ip)
    except ValueError as e :
        print(f"{RED}[+] {e}{NONE}")
        exit(-1)

#Check For Valid CIDR
def checkCIDR(netip):
    try :
        return ipaddress.ip_network(netip,False)
    except Exception as e :
        print(f"{RED}[+] {e}{NONE}")
        exit(-2)

#Print Available interfaces
def showlocalinterfaces():
    interfaces = []
    instance = psutil.net_if_addrs() #Get Information About Available Interfaces
    address_ip = []
    netmask_ip = []
    broadcast_ip = []
    for interface_name, interface_addresses in instance.items():
        interfaces.append(interface_name)
        for address in interface_addresses:
            if str(address.family) == 'AddressFamily.AF_INET': #Checking For TCP Connections
                address_ip.append(address.address)
                netmask_ip.append(address.netmask)
                broadcast_ip.append(address.broadcast)
    data = {"Interface"    : [*interfaces],
                "IP-Address"   : [*address_ip],
                "Netmask"      : [*netmask_ip],
                "Broadcast-IP" : [*broadcast_ip]
                }
    print(f'{GREEN}[+]Available Interfaces Are : \n{CYAN}{tabulate(data, headers="keys", tablefmt="pretty")}{NONE}\n')

#Scan a network for live hosts using Ping Sweep
def getlivehosts(ip):
    livehosts=list()
    netscan=networkscan.Networkscan(ip)
    netscan.run() #Run A Ping Sweep Across The Network
    for host in netscan.list_of_hosts_found :
        livehosts.append(host)
    return livehosts

#Get User Input
def getuserinput():
    host=input(f"{GREEN}[+] Enter Local IP of Address You Want To Listen On : {NONE}")
    checkIP(host)
    target=input(f"{YELLOW}[+] Enter Victim's IP : {NONE}")
    checkIP(target)
    try :
        cidr=input(f"{BLUE}[+] Enter CIDR (Default=24) : {NONE}")
        if cidr=='':
            cidr=24
        else :
            cidr=int(cidr)
        checkCIDR(f"{host}/{str(cidr)}")
    except ValueError as e :
        print(f"{PURPLE}[+] Invalid Input. Using Default Value !")
        cidr=24
    return [host,target,cidr]

#Check If Attacker and Victim are on the Same network or not
def checkSame(host,target,cidr):
    netip=f"{host}/{cidr}"
    if checkIP(target) in ipaddress.ip_network(netip,False):
        return (str((ipaddress.ip_network(netip,False))[0]))
    else :
        print(f"{RED}[+] Attacker And Victim Are Not In The Same Network!{NONE}")
        exit(-3)

#Perform Ping Sweep
def pingsweep(ip,cidr):
    live=list()
    print(f"{PURPLE}[+] Performing A PingSweep{NONE}")
    live=getlivehosts(f"{ip}/{cidr}")
    if len(live)==0 :
        choice=input(f"{YELLOW}[-] No Live Hosts Detected. Continue Anyway [y/N]?")
        if choice=="" or qchoice.lower()=='n' :
            exit(-4)
        else :
            for allip in ipaddress.ip_network(f"{ip}/{cidr}"):
                live.append(allip)
    return live

#Main Function to call other functions
def main():
    #Show Available interfaces
    showlocalinterfaces()
    #Get Input information
    userinput=getuserinput()
    #Check If Same Network
    nhost=(checkSame(userinput[0],userinput[1],userinput[2]))
    #Performing A Ping Sweep

    live=pingsweep(nhost,userinput[2])
    print(live)

if __name__=='__main__':
    main()
