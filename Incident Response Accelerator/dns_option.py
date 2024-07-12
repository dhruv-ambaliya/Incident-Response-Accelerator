import datetime
import os
import re

import config
import socket
from ipwhois import IPWhois
from spyse import Client
from urllib.parse import urlparse

# def menu():
#     print("\n")
#     print("-----------")
#     print("DNS OPTIONS")
#     print("-----------")
#
#     print("\nPlease select an option from below : ")
#     print("OPTION 1: Check for Reverse DNS Lookup")
#     print("OPTION 2: DNS Lookup")
#     print("OPTION 3: WHOIS Lookup")
#     print("OPTION 4: ISP Lookup")
#     print("OPTION 0: Exit")
#     dnsmenu(int(input()))
#
# def dnsmenu(selected_option):
#
#     if selected_option == 1 :
#         reversedns()
#     elif selected_option == 2 :
#         dnslookup()
#     elif selected_option == 3 :
#         whoislookup()
#     elif selected_option == 4 :
#         isplookup()
#     elif selected_option == 0 :
#         return
#     else :
#         print("Incorrect input")
#         menu()
#
# def reversedns():
#     ip_address = str(input("Enter IP Address to check :").strip())
#
#     print("\n")
#     print("------------------")
#     print("REVERSE DNS RECORD")
#     print("------------------")
#
#     try:
#         client = Client(config.key_dictionary['Spyse API Key'])
#         ip_details = client.get_ip_details(ip_address)
#         print("\nIP Address  :", ip_details.ip)
#         if str(ip_details.ports) != "None" :
#             print("Domain Name   :", str(ip_details.ports[0].http_extract.final_redirect_url.host))
#             print("Full URL      :", str(ip_details.ports[0].http_extract.final_redirect_url.full_uri))
#         print("ISP Details   :", str(ip_details.isp_info))
#         menu()
#     except:
#         print("Hostname for give IP not found")
#         menu()
#
# def dnslookup():
#     hostname = str(input("Enter Domain Name/URL to check :").strip())
#     final_domain = urlparse(hostname).netloc
#
#     print("\n")
#     print("----------")
#     print("DNS RECORD")
#     print("----------")
#
#     try:
#         if final_domain == '':
#             ip_address = socket.gethostbyname(hostname)
#             client = Client(config.key_dictionary['Spyse API Key'])
#             domain_details = client.get_domain_details(hostname)
#         else:
#             ip_address = socket.gethostbyname(final_domain)
#             client = Client("44801a9c-61b5-41be-a005-7b283bb3e2a1")
#             domain_details = client.get_domain_details(final_domain)
#         print("\nIP Address    :", ip_address)
#         print("Organization    :", str(domain_details.cert_summary.subject.organization))
#         print("Country         :", str(domain_details.cert_summary.subject.country))
#         print("Full DNS Report :", str(domain_details.dns_records))
#         print("ISP Details     :", str(domain_details.hosts_enrichment))
#         menu()
#     except:
#         print("IP Address for give domain name not found")
#         menu()
#
# def whoislookup():
#
#     ip = str(input("Enter IP Address to check :").strip())
#
#     try:
#         client = Client(config.key_dictionary['Spyse API Key'])
#         ip_details = client.get_ip_details(ip)
#         obj = IPWhois(ip)
#         res = obj.lookup_whois()
#         addr = str(res['nets'][0]['address'])
#         addr = addr.replace('\n', ', ')
#         print("\n")
#         print("------------")
#         print("WHOIS RECORD")
#         print("------------")
#         print("CIDR         :" + str(res['nets'][0]['cidr']))
#         print("Name         :" + str(res['nets'][0]['name']))
#         print("Range        :" + str(res['nets'][0]['range']))
#         print("Descr        :" + str(res['nets'][0]['description']))
#         print("Country      :" + str(res['nets'][0]['country']))
#         print("Address      :" + addr)
#         if str(ip_details.ports) != "None" :
#             print("Domain Name   :", str(ip_details.ports[0].http_extract.final_redirect_url.host))
#             print("Full URL      :", str(ip_details.ports[0].http_extract.final_redirect_url.full_uri))
#         print("ISP Details  :", str(ip_details.isp_info))
#         print("Created      :" + str(res['nets'][0]['created']))
#         print("Updated      :" + str(res['nets'][0]['updated']))
#         menu()
#     except:
#         print("Invalid or Private IP Address")
#         menu()
#
# def isplookup() :
#     ip_address = str(input("Enter IP Address to check :").strip())
#     print("\n")
#     print("----------")
#     print("ISP RECORD")
#     print("----------")
#     try:
#         client = Client(config.key_dictionary['Spyse API Key'])
#         ip_details = client.get_ip_details(ip_address)
#         print("\nIP Address    :", ip_details.ip)
#         print("AS Number       :", str(ip_details.isp_info.as_num))
#         print("AS Organization :", str(ip_details.isp_info.as_org))
#         print("ISP             :", str(ip_details.isp_info.isp))
#         print("City Name       :", str(ip_details.geo_info.city_name))
#         print("City Name       :", str(ip_details.geo_info.country))
#         print("City Name       :", str(ip_details.geo_info.country_iso_code))
#         print("Location        :", str(ip_details.geo_info.location))
#         if str(ip_details.ports) != "None" :
#             print("Domain Name   :", str(ip_details.ports[0].http_extract.final_redirect_url.host))
#             print("Full URL      :", str(ip_details.ports[0].http_extract.final_redirect_url.full_uri))
#         menu()
#     except:
#         print("Hostname for give IP not found")
#         menu()


def dnsSwitch(choice):
    if choice == '1':
        reverseDnsLookup()
    if choice == '2':
        dnsLookup()
    if choice == '3':
        whoIs()
    if choice == '0':
        # mainMenu()
        return
def dnsMenu():
    print("\n --------------------------------- ")
    print("         D N S    T O O L S        ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: Reverse DNS Lookup")
    print(" OPTION 2: DNS Lookup")
    print(" OPTION 3: WHOIS Lookup")
    print(" OPTION 0: Exit to Main Menu")
    # dnsmenu(int(input()))

    dnsSwitch(input())

def reverseDnsLookup():
    d = str(input(" Enter IP to check: ").strip())
    try:
        s = socket.gethostbyaddr(d)
        print('\n ' + s[0])
    except:
        print(" Hostname not found")
    dnsMenu()

def dnsLookup():
    d = str(input(" Enter Domain Name to check: ").strip())
    d = re.sub("http://", "", d)
    d = re.sub("https://", "", d)
    try:
        s = socket.gethostbyname(d)
        print('\n ' + s)
    except:
        print("Website not found")
    dnsMenu()

def whoIs():
    ip = str(input(' Enter IP / Domain: ').strip())
    whoIsPrint(ip)

    dnsMenu()

def whoIsPrint(ip):
    try:
        w = IPWhois(ip)
        w = w.lookup_whois()
        addr = str(w['nets'][0]['address'])
        addr = addr.replace('\n', ', ')
        print("\n WHO IS REPORT:")
        print("  CIDR:      " + str(w['nets'][0]['cidr']))
        print("  Name:      " + str(w['nets'][0]['name']))
        # print("  Handle:    " + str(w['nets'][0]['handle']))
        print("  Range:     " + str(w['nets'][0]['range']))
        print("  Descr:     " + str(w['nets'][0]['description']))
        print("  Country:   " + str(w['nets'][0]['country']))
        print("  State:     " + str(w['nets'][0]['state']))
        print("  City:      " + str(w['nets'][0]['city']))
        print("  Address:   " + addr)
        print("  Post Code: " + str(w['nets'][0]['postal_code']))
        # print("  Emails:    " + str(w['nets'][0]['emails']))
        print("  Created:   " + str(w['nets'][0]['created']))
        print("  Updated:   " + str(w['nets'][0]['updated']))

        now = datetime.now() # current date and time
        today = now.strftime("%m-%d-%Y")
        if not os.path.exists('output/'+today):
            os.makedirs('output/'+today)
        f= open('output/'+today+'/'+str(ip.split()) + ".txt","a+")

        f.write("\n ---------------------------------")
        f.write("\n WHO IS REPORT:")
        f.write("\n ---------------------------------\n")
        f.write("\n CIDR:      " + str(w['nets'][0]['cidr']))
        f.write("\n Name:      " + str(w['nets'][0]['name']))
        # print("  Handle:    " + str(w['nets'][0]['handle']))
        f.write("\n Range:     " + str(w['nets'][0]['range']))
        f.write("\n Descr:     " + str(w['nets'][0]['description']))
        f.write("\n Country:   " + str(w['nets'][0]['country']))
        f.write("\n State:     " + str(w['nets'][0]['state']))
        f.write("\n City:      " + str(w['nets'][0]['city']))
        f.write("\n Address:   " + addr)
        f.write("\n Post Code: " + str(w['nets'][0]['postal_code']))
        # print("  Emails:    " + str(w['nets'][0]['emails']))
        f.write("\n Created:   " + str(w['nets'][0]['created']))
        f.write("\n Updated:   " + str(w['nets'][0]['updated']))
        f.close();
        c = 0
    except:
        print("\n  IP Not Found - Checking Domains")
        ip = re.sub('https://', '', ip)
        ip = re.sub('http://', '', ip)
        try:
            if c == 0:
                s = socket.gethostbyname(ip)
                print( '  Resolved Address: %s' % s)
                c = 1
                whoIsPrint(s)
        except:
            print(' IP or Domain not Found')
    return