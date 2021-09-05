import os
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11, RadioTap, Dot11Deauth
from scapy.all import *

# MAC address of AP to defend
defAP = ""

# counting how many packet he acess point recieved 
counter = 0

# A list of all Aacess point MACs scanned
scannedMac = {}

def filter_packets(packet):
    global scannedMac
    if packet.type == 0 and packet.subtype == 8:
        if packet.addr2 not in scannedMac:
            scannedMac[packet.addr2] = packet.addr2
            print(len(scannedMac), '     %s     %s ' % (packet.addr2, packet.info))

# finding how much deauth attacks occured
def defense(packet):
    global defAP
    client = packet[Dot11].addr3
    global counter
    # packet type 0 and subtype 12 is deauthentication packet.
    if(packet.type == 0):
        if(packet.subtype == 12):
            if(client == defAP):
                counter+=1
    # If we get more than 100 packets
    if(counter > 100):
        print("we are under attack !")


def main():
# Code to switch to monitor mode (equals to airmon-ng)
    os.system('iwconfig')
    networkCard = input("Enter the name of the network card you want to switch to monitor mode: \n")
    os.system('sudo ifconfig ' + networkCard + ' down')
    os.system('sudo iwconfig ' + networkCard + ' mode monitor')
    os.system('sudo ifconfig ' + networkCard + ' up')
    os.system('iwconfig')
    print("Scanning for access points, please wait... or press CTRL+C to stop scanning")
    print("index         MAC            SSID")
    sniff(iface=networkCard, prn=filter_packets)
    defAP = input('Please enter the mac-address for defense: ')
    sniff(iface=networkCard, prn=defense)

main()
