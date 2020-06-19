def read_packet(filename):
    f = open(filename, "r")
    lines = f.readlines()
    hexdump = []
    hexdumps = []
    for line in lines:
        x = line.strip()
        hd = list(x)
        if hd == []:
            continue
        ind = hd[:4]
        if ind[0] == '0' and ind[1] == '0' and ind[2] == '0' and ind[3] == '0':
            hexdumps.append(hexdump)
            hexdump = []
        hd = hd[5:53]
        for i in hd:
            if i == ' ':
                continue
            hexdump.append(i)
    hexdumps.append(hexdump)
    f.close()

    # for hexdump in hexdumps:
    #     print(hexdump)

    return hexdumps[1:]


def isSubArray(A, B, n, m): 
    i = 0
    j = 0   
    while (i < n and j < m): 
        if (A[i] == B[j]): 
            i += 1
            j += 1 
            if (j == m): 
                return True 
        else: 
            i = i - j + 1 
            j = 0 
    return False 


def get_mac(l):
    mac = ""
    for i in range(len(l)):
        mac = mac + l[i]
        if i % 2 == 1:
            mac = mac + ":"
    return mac[:len(mac)-1]

def get_hex_str(l):
    s = "".join(l)
    return s

def get_ethernet_header(hexdump):
    dest_mac_add = hexdump[:12]
    src_mac_add = hexdump[12:24]
    eth_type = hexdump[24:28]

    ethernet_header = []
    ethernet_header.append(dest_mac_add)
    ethernet_header.append(src_mac_add)
    ethernet_header.append(eth_type)

    return ethernet_header

def display_ethernet_header(eth, out):
    print("Ethernet Header: ")
    mac = eth[0]
    mac_dest = get_mac(mac)
    mac = eth[1]
    mac_src = get_mac(mac)
    print("Desination MAC address: ", mac_dest)
    print("Source MAC address: ", mac_src)
    # If eth[2] = 08 00 ==> IP, eth[2] = 08 06 ==> ARP
    print("Ethernet Type: ", get_hex_str(eth[2]))
    if eth[2] == ['0', '8', '0', '0']:
        print("IP Packet")
    elif  eth[2] == ['0', '8', '0', '6']:
        print("ARP Packet")
    elif  eth[2] == ['8', '0', '3', '5']:
        print("RARP Packet") 
    elif eth[2] == ['8', '8', 'c', 'c']:
        print("LLDP Packet")
    elif eth[2] == ['8', '8', '0', '9']:
        print("Slow Protocol Packet")
    else:
        print("Packet type not recognised")

    print()
    return None

def get_ip_4(l):
    ip = ""
    p1 = "" + l[0] + l[1]
    p2 = "" + l[2] + l[3]
    p3 = "" + l[4] + l[5]
    p4 = "" + l[6] + l[7]
    ip1 = int(p1, 16)
    ip2 = int(p2, 16)
    ip3 = int(p3, 16)
    ip4 = int(p4, 16)
    ip = ip + str(ip1) + "." + str(ip2) + "." + str(ip3) + "." + str(ip4)
    return ip

def get_dec(l):
    p = "".join(l)
    p = int(p, 16)
    return p


def display_ip_header(iph):
    print("IP Header: ")
    print("Version: ", int(iph[0][0]))
    if iph[0] == ['4']:
        print("IPv4 Version")
    elif iph[0] == ['6']:
        print("IPv6 Version")
    print("IP Header Length: ", iph[1][0])
    if iph[0] == ['4']:
        print("( ", int(iph[1][0])*4, " bytes )")
    elif iph[0] == ['6']:
        print("( ", int(iph[1][0])*4, " ? bytes )") 
    print("Type of Service: ", iph[2][0])
    print("Explicit Congestion Notification: ", iph[3][0])
    print("IP Packet Length: ", get_hex_str(iph[4]))
    print("( ", get_dec(iph[4]), " bytes )")
    print("Identification: ", get_hex_str(iph[5]))
    print("Fragment offset: ", get_hex_str(iph[6]))
    print("Time to Live: ", get_hex_str(iph[7]))
    print("Protocol: ", get_hex_str(iph[8]))
    print("Header Checksum: ", get_hex_str(iph[9]))
    sip = get_ip_4(iph[10])
    dip = get_ip_4(iph[11])
    print("Source IP Address: ", sip)
    print("Destination IP Address: ", dip)
    print()
    if iph[8] == ['1', '1']:
        print("UDP Protocol:")
        sp = get_dec(iph[12][0])
        dp = get_dec(iph[12][1])
        l = get_dec(iph[12][2])
        chsum = iph[12][3]
        print("Source Port: ", sp)
        print("Destination Port: ", dp)
        print("Length: ", l)
        print("Checksum: ",get_hex_str(chsum))
        if iph[12][4]:
            print("Magic cookie: DHCP")
            print()
            print("DHCP Protocol")
        print()

    elif iph[8] == ['0', '6']:
        print("TCP Protocol:")
        sp = get_dec(iph[12][0])
        dp = get_dec(iph[12][1])
        print("Source Port: ", sp)
        print("Destination Port: ", dp)
        print("Sequence Number: ", get_hex_str(iph[12][2]))
        print("Acknowledgement Number: ", get_hex_str(iph[12][3]))
        print("Checksum: ", get_hex_str(iph[12][7]))
        print()

    elif iph[8] == ['0', '1']:
        print("ICMP Protocol:")
        tp = iph[12][0]
        code = iph[12][1]
        chsum = iph[12][2]
        identifier = iph[12][3]
        seq_no = iph[12][4]
        if(tp == ['0', '0']):
            print("ICMP type: 0 - Echo (ping) reply")
        elif(tp == ['0', '8']):
            print("ICMP type: 8 - Echo (ping)")
        else:
            print("ICMP type: ", tp[0], tp[1])
        print("Code: ", get_dec(code))
        print("Checksum: ", get_hex_str(chsum))
        print("Identifier: ", get_hex_str(identifier))
        print("Sequence Number: ", get_hex_str(seq_no))

    elif iph[8] == ['0', '2']:
        print("IGMP Protocol:")
        print("Membership Query: ", get_hex_str(iph[12][0]))
        print("Max Response Time (in sec): ", get_dec(iph[12][1])/10)
        print("Checksum: ", get_hex_str(iph[12][2]))
        print("Multicast Address: ", get_ip_4(iph[12][3]))

    else:
        print("Protocol not recognised")
    print() 


def parse_ip(hexdump, start):
    orig_start = start
    version = hexdump[start:start+1]
    ihl = hexdump[start+1:start+2]
    dscp = hexdump[start+2:start+3]
    ecn = hexdump[start+3:start+4]
    tot_length = hexdump[start+4:start+8]
    start = start + 8
    identification = hexdump[start:start+4]
    fragment = hexdump[start+4:start+8]
    start = start + 8
    time_to_live = hexdump[start:start+2]
    protocol = hexdump[start+2:start+4]
    header_checksum = hexdump[start+4:start+8] 
    start = start + 8
    src_address =  hexdump[start:start+8]
    start = start + 8
    dest_address =  hexdump[start:start+8]
    start = start + 8

    udp_header = []
    tcp_header = []
    icmp_header = []
    igmp_header = []
    
    if protocol == ['1', '1']:
        udp_src_port = hexdump[start:start+4]
        udp_dest_port = hexdump[start+4:start+8]
        udp_length = hexdump[start+8:start+12]
        udp_checksum = hexdump[start+12:start+16]
        udp_header.append(udp_src_port)
        udp_header.append(udp_dest_port)
        udp_header.append(udp_length)
        udp_header.append(udp_checksum)
        dhcp = isSubArray(hexdump, ['6', '3', '8', '2', '5', '3', '6', '3'], len(hexdump), 8)
        udp_header.append(dhcp)

    elif protocol == ['0', '6']:
        tcp_src_port = hexdump[start:start+4]
        tcp_dest_port = hexdump[start+4:start+8]
        tcp_seq_no = hexdump[start+8:start+16]
        tcp_ack_no = hexdump[start+16:start+24]
        tcp_seg_len = hexdump[start+24:start+26]
        tcp_cwr = hexdump[start+26:start+28]
        tcp_window_size = hexdump[start+28:start+32]
        tcp_checksum = hexdump[start+32:start+36]
        tcp_urgent_pointer = hexdump[start+36:start+40]
        tcp_header.append(tcp_src_port)
        tcp_header.append(tcp_dest_port)
        tcp_header.append(tcp_seq_no)
        tcp_header.append(tcp_ack_no)
        tcp_header.append(tcp_seg_len)
        tcp_header.append(tcp_cwr)
        tcp_header.append(tcp_window_size)
        tcp_header.append(tcp_checksum)
        tcp_header.append(tcp_checksum)
        tcp_header.append(tcp_urgent_pointer)

    elif protocol == ['0', '1']:
        icmp_type = hexdump[start:start+2]
        icmp_code = hexdump[start+2:start+4]
        icmp_checksum = hexdump[start+4:start+8]
        icmp_identifier = hexdump[start+8:start+12]
        icmp_seq_no = hexdump[start+12:start+16]
        icmp_header.append(icmp_type)
        icmp_header.append(icmp_code)
        icmp_header.append(icmp_checksum)
        icmp_header.append(icmp_identifier)
        icmp_header.append(icmp_seq_no)
    
    elif protocol == ['0', '2']:
        l = get_dec(tot_length)
        start = orig_start + (2*l) - 16
        igmp_memq = hexdump[start:start+2]
        igmp_maxresptime = hexdump[start+2:start+4]
        igmp_checksum = hexdump[start+4:start+8]
        igmp_multaddr = hexdump[start+8:start+16]
        igmp_header.append(igmp_memq)
        igmp_header.append(igmp_maxresptime)
        igmp_header.append(igmp_checksum)
        igmp_header.append(igmp_multaddr)

    else:
        print("not tcp/udp/icmp/igmp header")

    ip_header = []
    ip_header.append(version)
    ip_header.append(ihl)
    ip_header.append(dscp)
    ip_header.append(ecn)
    ip_header.append(tot_length)
    ip_header.append(identification)
    ip_header.append(fragment)
    ip_header.append(time_to_live)
    ip_header.append(protocol)
    ip_header.append(header_checksum)
    ip_header.append(src_address)
    ip_header.append(dest_address)
    if protocol == ['1', '1']:
        ip_header.append(udp_header)
    elif protocol == ['0', '6']:
        ip_header.append(tcp_header)
    elif protocol == ['0', '1']:
        ip_header.append(icmp_header)
    elif protocol == ['0', '2']:
        ip_header.append(igmp_header)

    display_ip_header(ip_header)


def display_arp_header(ah, flag):
    if flag:
        print("ARP:")
    else:
        print("RARP:")
    print("Hardware Type: ", get_hex_str(ah[0]))
    if ah[0] == ['0', '0', '0', '1']:
        print("( Ethernet (1) )")
    print("Protocol Type: ", get_hex_str(ah[1]))
    if ah[1] == ['0', '8', '0', '0']:
        print("IPv4 Protocol")
    print("Hardware Size: ", get_hex_str(ah[2]))
    print("Protocol Size: ", get_hex_str(ah[3]))
    print("Opcode: ", get_hex_str(ah[4]))
    if get_dec(ah[4]) == 1:
        print("Request")
    elif get_dec(ah[4]) == 2:
        print("Reply")
    if get_dec(ah[4]) == 3:
        print("Reverse Request")
    elif get_dec(ah[4]) == 4:
        print("Reverse Reply")
    print("Sender MAC address: ", get_mac(ah[5]))
    print("Target MAC address: ", get_mac(ah[7]))
    if ah[1] == ['0', '8', '0', '0']:
        print("Sender IP address: ", get_ip_4(ah[6]))
        print("Target IP address:", get_ip_4(ah[8]))
        print()
    else:
        print("Sender IP address: ", ah[6])
        print("Target IP address:", ah[8])

    print()


def parse_arp(hexdump, start, flag):
    hardware_type = hexdump[start:start+4]
    protocol = hexdump[start+4:start+8]
    hardware_size = hexdump[start+8:start+10]
    protocol_size = hexdump[start+10:start+12]
    opcode = hexdump[start+12:start+16]
    sender_mac = hexdump[start+16:start+28]
    sender_ip = hexdump[start+28:start+36]
    target_mac = hexdump[start+36:start+48]
    target_ip = hexdump[start+48:start+56]

    arp_header = []
    arp_header.append(hardware_type)
    arp_header.append(protocol)
    arp_header.append(hardware_size)
    arp_header.append(protocol_size)
    arp_header.append(opcode)
    arp_header.append(sender_mac)
    arp_header.append(sender_ip)
    arp_header.append(target_mac)
    arp_header.append(target_ip)

    display_arp_header(arp_header, flag)


def parse_print_lldp(hexdump, start):
    orig_start = start
    print("LLDP Protocol:")

    while True:
        tlv_type = hexdump[start:start+2]
        if tlv_type == ['0', '2']:
            print("TLV Type: Chassis Id (1)")
            print("TLV Length: 7")
            id = hexdump[start+4:start+6]
            print("Chassis Id Subtype: ", get_dec(id))
            if(get_dec(id) == 4):
                print("(MAC Address)")
            print("Chassis Id: ", get_mac(hexdump[start+6:start+18]))
            start += 18

        elif tlv_type == ['0', '4']:
            print("TLV Type: Port Id (2)")
            print("TLV Length: 4")
            id = hexdump[start+4:start+6]
            print("Port Id Subtype: ", get_dec(id))
            if(get_dec(id) == 5):
                print("(Interface name)")
            print("Port Id: ", get_hex_str(hexdump[start+6:start+12]))
            start += 12

        elif tlv_type == ['0', '6']:
            print("TLV Type: Time to Live (3)")
            print("TLV Length: 2")
            time = hexdump[start+4:start+8]
            print("Time(Seconds): ", get_dec(time))
            start += 8
        
        else:
            break


def parse_print_lacp(hexdump, start):
    orig_start = start
    print("LACP Version: ", get_hex_str(hexdump[start:start+2]))
    start += 2
    while True:
        print("TLV Type: ", get_hex_str(hexdump[start:start+2]))
        if get_dec(hexdump[start:start+2]) == 1:
            print("(Actor Information)")
            print("TLV Length: ", get_hex_str(hexdump[start+2:start+4]))
            print("Actor System Priority: ", get_dec(hexdump[start+4:start+8]))
            print("Actor System ID: ", get_mac(hexdump[start+8:start+20]))
            print("Actor Key: ", get_dec(hexdump[start+20:start+24]))
            print("Actor Port Priority: ", get_dec(hexdump[start+24:start+28]))
            print("Actor Port: ", get_dec(hexdump[start+28:start+32]))
            print("Actor State: ", get_hex_str(hexdump[start+32:start+34]))
            start += 40
        elif get_dec(hexdump[start:start+2]) == 2:
            print("(Partner Information)")
            print("TLV Length: ", get_hex_str(hexdump[start+2:start+4]))
            print("Partner System Priority: ", get_dec(hexdump[start+4:start+8]))
            print("Partner System: ", get_mac(hexdump[start+8:start+20]))
            print("Partner Key: ", get_dec(hexdump[start+20:start+24]))
            print("Partner Port Priority: ", get_dec(hexdump[start+24:start+28]))
            print("Partner Port: ", get_dec(hexdump[start+28:start+32]))
            print("Partner State: ", get_hex_str(hexdump[start+32:start+34]))
            start += 40
        elif get_dec(hexdump[start:start+2]) == 3:
            print("(Collector Information)")
            print("TLV Length: ", get_hex_str(hexdump[start+2:start+4]))
            print("Collector Max Delay: ", get_dec(hexdump[start+4:start+8]))
            start += 32
        elif get_dec(hexdump[start:start+2]) == 0:
            print("(Terminator)")
            print("TLV Length: ", get_hex_str(hexdump[start+2:start+4]))
            start += 4
            break
        else:
            break


def main():
    filename = "captured_packets_hex" # Name of file with hexdump
    hexdumps = read_packet(filename)
    i = 1
    # print()
    # print(hexdumps)
    for hexdump in hexdumps:
        print()
        print("============ ", i, " ============")
        i += 1
        ethernet_header = get_ethernet_header(hexdump)
        display_ethernet_header(ethernet_header, None)
        if ethernet_header[2] == ['0', '8', '0', '0']:
            parse_ip(hexdump, 28)
        elif ethernet_header[2] == ['0', '8', '0', '6']:
            parse_arp(hexdump, 28, True)
        elif ethernet_header[2] == ['8', '0', '3', '5']:
            parse_arp(hexdump, 28, False)
        elif ethernet_header[2] == ['8', '8', 'c', 'c']:
            parse_print_lldp(hexdump, 28)
        elif ethernet_header[2] == ['8', '8', '0', '9']:
            if hexdump[28:30] == ['0', '1']:
                print("LACP Protocol (Slow Protocol subtype: 0x01)")
                parse_print_lacp(hexdump, 30)
            else:
                print("Slow Protocols")
        else:
            print("Protocol Not Recognised")


main()