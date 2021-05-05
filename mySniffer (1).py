import socket
import struct
import textwrap
import binascii


TAB_1 = '\t '
TAB_2 = '\t\t '
TAB_3 = '\t\t\t '
TAB_4 = '\t\t\t\t '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

tcpCount = 0
udpCount = 0
icmpCount = 0

ipArray = []
countArray = []

fragg = 0

plplpl = 0

packetSize = [] 
countPacket = 0
packet_sum = 0

def main():

    global tcpCount,udpCount,icmpCount,countPacket,packet_sum
    countArray.append(0)
    for i in range(1,100):
        countArray.append(1)      
    
    open('result.txt', 'w').close()
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    try:
        ipArray.append(0)
        while True:
            raw_data, addr = conn.recvfrom(65536)
            countPacket += 1
            data_offset = 0
            eth_proto, data = ethernet_frame(raw_data)

            # 8 for IPv4
            if eth_proto == 8:
                (total_length, ihl, src_ip, proto, data) = ipv4_packet(data)
                flag = 1
                for i in range(0,len(ipArray)):
                    if ipArray[i] == src_ip:
                        countArray[i] += 1
                        flag = 0
                if flag == 1:   
                    ipArray.append(src_ip)

                # ICMP
                if proto == 1:
                    data = icmp_packet(data)
                    icmpCount += 1
                    
                # TCP
                elif proto == 6:
                    data_offset,data = tcp_segment(data)
                    tcpCount += 1

                # UDP
                elif proto == 17:
                    data = udp_segment(data)
                    udpCount += 1

                 # Other
                else:
                    print(TAB_1 + 'Data:')
                    print(TAB_2 + format_multi_line(DATA_TAB_2, data))
                    
                # [IP Total Length] - ( ([IP IHL] + [TCP Data offset]) * 4 )
                #aa =  (total_length) - ( (ihl + data_offset) * 4 )  #this is packet size excluding the header information 
                aa = total_length #Total Length field that gives the length of the entire IP packet in bytes
                packetSize.append(aa)
 
            else:
                print('Data:')
                print(format_multi_line(DATA_TAB_1, data))
                
                
    except KeyboardInterrupt: #handle the exception of ^c in terminal
        print("Keyboard Interrupt Exception")
    
    result = open("result.txt", "a")
    result.write("total number of ICMP packets :\n")
    result.write(str(icmpCount))
    result.write('\n')
    result.write("total number of TCP packets :\n")
    result.write(str(tcpCount))
    result.write('\n')
    result.write("total number of UDP packets :\n")
    result.write(str(udpCount))
    result.write('\n')
    result.write('\nsorted number of packets for each source IP address:')
    result.write('\n') 
   
    print('\n\n udp :{}  , tcp :{}  , icmp :{} \n\n\n'.format(udpCount,tcpCount,icmpCount))
    ok = len(ipArray)
    for l in range(1,ok):
        k = 0
        for i in range(0,ok):
            temp = countArray[i]
            for j in range(0,ok):
                if temp < countArray[j]:
                    temp = countArray[j]
                    k = j      
        print('{} ==> {}' .format(ipArray[k], countArray[k]))
        result.write(str(ipArray[k]) + ' ==> ' + str(countArray[k]))
        result.write('\n')
        countArray.pop(k)
        ipArray.pop(k)
    
    for i in range(0, countPacket):
        temp_max = packetSize[i]
        temp_min = packetSize[i]
        for j in range(0,countPacket):
            if temp_max < packetSize[j]:
                temp_max = packetSize[j]
            elif temp_min > packetSize[j]:
                temp_min = packetSize[j]              
    for i in range (0,countPacket):
        packet_sum += packetSize[i]
        
    avg = packet_sum / countPacket
    
    bb = countPacket - fragg #the packets with DF = 0 are consider as fragmented packets
    
    result.write('\nnumber of fragmented packets : ')
    result.write(str(bb))
          
    result.write('\n\n>>size of packets')    
    result.write('\nminimum size : ')
    result.write(str(temp_min))
    result.write('\nmaximum size : ') 
    result.write(str(temp_max))
    result.write('\naverage size : ')    
    result.write(str(avg)) 
    

                                  
    result.close()
    

    print("\nnumber of fragmented packets : {}".format(bb))
    print("total packet number : {}".format(countPacket))
    #print("packet size array: {}".format(packetSize))
    print("min packet size : {}".format(temp_min))
    print("max packet size : {}".format(temp_max))  
    print("avg packet size : {}".format(avg))      
# Unpack Ethernet Frame
def ethernet_frame(data):

    eth_hdr = struct.unpack("! 6s 6s H", data[0:14]) #! means network/
    # 6s means a single string with 6 characters(6bytes) first one
    # for destination mac and other one for source mac/
    # H means an unsigned int with 2 bytes for ethernet type
    binary_dest_mac = binascii.hexlify(eth_hdr[0]) # Destination address
    binary_src_mac  = binascii.hexlify(eth_hdr[1]) # Source address
    dest_mac = binary_dest_mac.decode('ascii')
    src_mac = binary_src_mac.decode('ascii')
    proto  = eth_hdr[2] >> 8
    print ("\n****************** ETHERNET HEADER ******************\n")
    print ("> Destination MAC: " + dest_mac[0:2] + ':' + dest_mac[2:4] + ':' +
     dest_mac[4:6] + ':' + dest_mac[6:8] + ':' + dest_mac[8:10] + ':' + dest_mac[10:12])
    print ("> Source MAC: " + src_mac[0:2] + ':' + src_mac[2:4] + ':' + src_mac[4:6] 
     + ':' + src_mac[6:8] + ':' + src_mac[8:10] + ':' + src_mac[10:12])
    print ("> Protocol: {}" .format(proto))
    return proto, data[14:]
    

# Unpack the IPv4 packet
def ipv4_packet(data): 
    global fragg

    ip_hdr = struct.unpack("! 6H 4s 4s", data[0:20])#! means network/
    #6H means 6 int with the size 2 bytes  for the first 12 byte of data of IPv4 header
    # 4s means a single string with 4 characters(4 bytes) first one
    # for source address and other one for destination address/
	
    version = ip_hdr[0] >> 12 #first 4 bit of 16 bit ---> 16-4=12 
    ihl = (ip_hdr[0] >> 8) & 0x0f #15
    tos = ip_hdr[0] & 0x00ff #255
	
    length = ip_hdr[1]
	
    ip_id = ip_hdr[2]
	
    flags = ip_hdr[3] >> 13 #3 first bit for flag ---> 16-3=13

        
    do_not_frag = flags >> 1
    more_frag = flags & 0x1
    
    if do_not_frag == 1:
        fragg += 1
    
    
    frag_offset = ip_hdr[3] & 0x1fff #8191 = 2^12
	
    ip_ttl = ip_hdr[4] >> 8
    ip_protocol = ip_hdr[4] & 0x00ff #255 = 2^7
	
    chksum = ip_hdr[5]
	
    src_addr = socket.inet_ntoa(ip_hdr[6]) #Converts an IP address,
    # which is in 32-bit packed format to the popular human readable dotted-quad string format.
    
    dst_addr = socket.inet_ntoa(ip_hdr[7])

    print ("\n****************** IP HEADER ******************\n")
    print (TAB_1 + "> Version: {}".format(version) + " ---- IHL: {}".format(ihl) + " ----  Type Of Service: {}".format(tos) + 
    " ----  Total Length: {}".format(length) + " ----  ID: {}".format(ip_id) + " ---- Do Not Frag: {}".format(do_not_frag) + 
    " ----  More frag: {}".format(more_frag) + " ----  Offset: {}".format(frag_offset) + " ----  TTL: {}".format(ip_ttl) 
    + " ----  Next protocol: {}".format(ip_protocol) + " ----  Checksum: {}".format(chksum) + " ----  Source IP: {}".format(src_addr)
     + " ----  Dest IP: {}".format(dst_addr))

    
    data_length = length-(ihl*32)//8 #use // to aviod float
    return length, ihl, src_addr, ip_protocol, data[data_length:]


# Unpacks ICMP packet
def icmp_packet(data):

    icmp_header= struct.unpack('! B B H', data[0:4])
    icmp_type = icmp_header[0]
    code = icmp_hearder[1]
    checksum = icmp_header[2]
    print ('\n===== ICMP Packet =====\n')
    print(TAB_1 + '> Type: {} ----- Code: {} ----- Checksum: {}'.format(icmp_type, code, checksum))
    print(TAB_1 + 'Data:')
    print(format_multi_line(DATA_TAB_3, data))
    
    return data[4:]

# Unpacks TCP segment
def tcp_segment(data):
    
    global plplpl

    tcp_hdr = struct.unpack('! 2H 2L 4H', data[0:20])
    src_port = tcp_hdr[0]
    dest_port = tcp_hdr[1]
    sequence = tcp_hdr[2]
    acknowledgement = tcp_hdr[3]
    

    data_offset = (tcp_hdr[4] >> 12)	

    reserved = (tcp_hdr[4] & 63) >> 6 #MUST BE ZERO    

    if reserved > 0:
        plplpl += 1
        
    flag_urg = (tcp_hdr[4] & 32) >> 5
    flag_ack = (tcp_hdr[4] & 16) >> 4
    flag_psh = (tcp_hdr[4] & 8) >> 3
    flag_rst = (tcp_hdr[4] & 4) >> 2
    flag_syn = (tcp_hdr[4] & 2) >> 1
    flag_fin = tcp_hdr[4] & 1
    
    window  = tcp_hdr[5]
    checksum = tcp_hdr[6]
    urg_ptr = tcp_hdr[7]
    
    print('\n===== TCP Segment =====\n')
    print(TAB_1 + 'Source Port: {} ---- Destination Port: {}'.format(src_port, dest_port))
    print(TAB_1 + 'Sequence: {} ---- Acknowledgement: {}'.format(sequence, acknowledgement))
    print(TAB_1 + 'data offset: {} ---- reserved: {}'.format(data_offset, reserved))
    print(TAB_1 + 'Flags:')
    print(TAB_2 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN:{}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
    print(TAB_1 + 'window: {} ---- checksum: {} ---- urgent pointer: {}'.format(window, checksum, urg_ptr))
    print(TAB_1 + 'Data:')
    print(format_multi_line(DATA_TAB_3, data))
    
    return  data_offset, data[data_offset*4:]



#unpack UDP segment
def udp_segment(data):
    udp_hdr = struct.unpack('! 4H', data[0:8])
    src_port = udp_hdr[0]
    dest_port = udp_hdr[1]
    length = udp_hdr[2]
    checksum = udp_hdr[3]
    
    print('\n===== UDP Segment =====\n')
    print(TAB_1 + 'Source Port: {} --- Destination Port: {} --- Length: {} --- checksum: {}'.format(src_port, dest_port, length, checksum))
    
    return data[8:]

# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string) #seperate each byte with \x
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
main()


