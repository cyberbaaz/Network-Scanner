import scapy.all as scapy
import optparse
import requests
#from requests.exceptions import Timeout


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # print(arp_request.summary()) #check the summary of request
    # scapy.ls(scapy.ARP())  #for getting the list of fields
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # print(broadcast.summary()) #check the summary of broadcast
    # scapy.ls(scapy.Ether())  #for getting the list of fields for Ethernet frame
    req_broadcast = broadcast/arp_request  # linking is done
    # req_broadcast.show() #get details of fields with its value
    answered_list = scapy.srp(req_broadcast, timeout=2, verbose=False)[0]  # srp() returns two lists,use answered only

    clients_list = []
    for element in answered_list:
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}  # fields selected from show()
        clients_list.append(clients_dict)
    return clients_list


def print_result(client_list):
    print("-"*88)
    print("IP\t\tMAC Address\t\ttime/length\t\tVendor")
    print("-"*88)
    for client in client_list:
        vendor=requests.get('http://api.macvendors.com/' + client["mac"])
        exec_time = str(round(vendor.elapsed.total_seconds(),3))
        if vendor.status_code!=200:
            vendor_err="Not Found"
            print(client["ip"] +"\t" + client["mac"] + "\t" + exec_time + ","+str(vendor.headers['content-length']) + "\t\t" + vendor_err)
        else:
            print(client["ip"] +"\t" + client["mac"] + "\t" + exec_time + ","+str(vendor.headers['content-length']) + "\t\t" + vendor.text)



def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--target", dest="target", help="Enter the ip or netmask")
    (option, arguments) = parser.parse_args()
    if not option.target:
        parser.error("[-]Please specify the ip range")
    return option


list_ven = []
options = get_args()

scan_result = scan(options.target)
print_result(scan_result)

