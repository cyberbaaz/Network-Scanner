import scapy.all as scapy
import optparse


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
    print("-----------------------------------------")
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in client_list:
        print(client["ip"] +"\t\t" + client["mac"])


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--target", dest="target", help="Enter the ip or netmask")
    (option, arguments) = parser.parse_args()
    if not option.target:
        parser.error("[-]Please specify the ip range")
    return option


options = get_args()

scan_result = scan(options.target)
print_result(scan_result)
