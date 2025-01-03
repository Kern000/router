from scapy.all import *
import argparse
import threading
from functools import reduce


working = scapy.interfaces.get_working_ifaces()

#To match ethernet mac addr
print(IFACES)

print("\nchoose index from list of working NIC:\n")
for index, key in enumerate(working):
    print(index, 
          "NIC Device:", key, 
          "MAC Address:", get_if_hwaddr(working[index]))

choice = int(input("choose an index:"))

chosen_mac_addr1 = \
    get_if_hwaddr(ifaces.dev_from_networkname(working[choice]))
chosen_gateway_addr1 = \
    get_if_addr(ifaces.dev_from_networkname(working[choice]))
chosen_interface1 = \
    ifaces.dev_from_networkname(working[choice])
print(chosen_interface1)
print("you have chosen:", chosen_mac_addr1)
print("your gateway ip addr:", chosen_gateway_addr1)

choice2 = int(input("choose 2nd iface with an index:"))

chosen_mac_addr2 = \
    get_if_hwaddr(ifaces.dev_from_networkname(working[choice2]))
chosen_gateway_addr2 = \
    get_if_addr(ifaces.dev_from_networkname(working[choice2]))
chosen_interface2 = \
    ifaces.dev_from_networkname(working[choice2])
print(chosen_interface2)
print("you have chosen for 2nd iface:", chosen_mac_addr2)
print("your gateway ip addr:", chosen_gateway_addr2)


parser = argparse.ArgumentParser()
parser.add_argument("-i1", 
                    default="192.168.1.1", 
                    help="router interface 1")
parser.add_argument("-i1mask", 
                    default="255.255.255.0", 
                    help="subnet mask for interface 1")
parser.add_argument("-i2", 
                    default="10.0.0.1", 
                    help="router interface 2")
parser.add_argument("-i2mask", 
                    default="255.0.0.0", 
                    help="subnet mask for interface 2")
args = parser.parse_args()

network_1 = "192.168.1."
network_2 = "10."


def validate_interface_address(args):
    """validating valid ip addr format"""
    try:
        octets = args.split(".")

        if len(octets) != 4:
            raise ValueError()

        for octet in octets:
            if int(octet) < 0 or int(octet) > 255:
                raise ValueError()
        return True
    except:
        print("invalid interface address")
        return False


def validate_mask_address(args):
    """ 
    validating mask address based on bit values
    """
    try:
        octets = args.split(".")
        
        if len(octets) != 4:
            raise ValueError()

        discrete_bits = []
        cumulative_bits = []

        for i in range(0,8):
            discrete_bits.append(2**i)

        cumulative_bits.append(255)

        for i in range(len(discrete_bits)):
            sum = reduce(lambda acc, a: acc+a, 
                            discrete_bits[0:i+1])
            cumulative_bits.append(255-sum)

        for i in range(len(octets)):
            
            if int(octets[i]) not in cumulative_bits:
                
                raise ValueError()
            
            if int(octets[i]) != 255 \
               and int(octets[i]) != 0 \
               and i != 0:
                
                if int(octets[i-1]) != 255:
                    raise ValueError()
        
        return True
    
    except:
    
        print("invalid mask")
        return False


def network_portion(ipaddr, netmask):
    """deriving network portion of decimal ip addr"""

    octets = ipaddr.split(".")
    holder = []

    for octet in octets:
        binary = (bin(int(octet)))
        string = str(binary).lstrip("0b").zfill(8)
        holder.append(string)
    router_ip_addr_bin = ''.join(holder)

    netmask_octets = netmask.split(".")

    mask_holder = []

    for octet in netmask_octets:
        binary = (bin(int(octet)))
        string = str(binary).lstrip("0b").zfill(8)
        mask_holder.append(string) 
    router_mask_bin = ''.join(mask_holder)

    count = 0
    for char in router_mask_bin:
        if char == "1":
            count += 1

    network_portion = router_ip_addr_bin[0:count] + (32-count) * "0"
    
    processed_octet = []

    for i in range(0,len(network_portion),8):
        processed_octet.append(network_portion[i:i+8])

    decimal_octet_network = []

    for i in processed_octet:
        decimal_octet_network.append((int(i,2)))

    string_network_portion = ""

    for i in range(0, len(decimal_octet_network)):
        if decimal_octet_network[i] != 0 and i != 3:
            string_network_portion += str(decimal_octet_network[i]) + "."
        elif decimal_octet_network[i] != 0 and i == 3:
            string_network_portion += str(decimal_octet_network[i])

    return string_network_portion


try:
    if validate_interface_address(args.i1) \
        and validate_mask_address(args.i1mask):
        
        network_1 = network_portion(args.i1, args.i1mask)

    if validate_interface_address(args.i2) \
        and validate_mask_address(args.i2mask):
        network_2 = network_portion(args.i2, args.i2mask)
except:
    print("invalid ip addr")


def interface_1_sniffer(packet):
    """
    router interface 1 filter
    based on src and dst
    """

    global network_1
    global network_2

    if packet.haslayer(IP):
        
        if packet[IP].dst.startswith(network_2) and \
           packet[IP].src.startswith(network_1):

            send_thread = threading.Thread(target=sendp(packet))
            send_thread.start()
            send_thread.join()

            print(f"routed packet from {packet[IP].src} to {packet[IP].dst}")
            return packet


def interface_2_sniffer(packet):
    """
    router interface 2 filter
    based on src and dst
    """

    global network_1
    global network_2

    if packet.haslayer(IP):
        
        if packet[IP].dst.startswith(network_1) and \
           packet[IP].src.startswith(network_2):

            send_thread = threading.Thread(target=sendp(packet))
            send_thread.start()
            send_thread.join()

            print(f"routed packet from {packet[IP].src} to {packet[IP].dst}")
            return packet


def sniff_thread_interface1():
    """threading sniffing based on NIC choice"""

    print("sniffing 1")
    sniff(lfilter=interface_1_sniffer, iface=chosen_interface1, timeout=30)


def sniff_thread_interface2():
    """threading sniffing based on NIC choice"""
    
    print("sniffing 2")
    sniff(lfilter=interface_2_sniffer, iface=chosen_interface2, timeout=30)


def main():
    sniff_thread1 = threading.Thread(target=sniff_thread_interface1)
    sniff_thread2 = threading.Thread(target=sniff_thread_interface2)
    sniff_thread1.start()
    sniff_thread2.start()
    sniff_thread1.join()
    sniff_thread2.join()

if __name__ == "__main__":
    main()

