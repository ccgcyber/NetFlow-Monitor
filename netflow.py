#!/usr/bin/env python3

import socket, struct
from socket import inet_ntoa
import atexit

def make_mask(n):
    "return a mask of n bits as a long integer"
    return (2 << n-1) - 1

def dotted_to_num(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('=L', socket.inet_aton(ip))[0]

def network_mask(ip, bits):
    "Convert a network address to a long integer" 
    return dotted_to_num(ip) & make_mask(bits)

def address_in_network(ip, net):
   "Is an address in a network"
   return dotted_to_num(ip) & net == net

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48

LOCAL_MASK = network_mask("192.168.0.0", 24)
OPS = ("download", "upload")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 2055))

# Store IP -> name mappings
name_map = {}

name_data = {}

# Print totals on exit
def exit_handler():
    print (name_data)

atexit.register(exit_handler)


while True:
    buf, addr = sock.recvfrom(1500)

    # Unpack the header
    """
    /* 24 byte header */
    struct ftpdu_v5 {
      u_int16 version; /* 5 */
      u_int16 count; /* The number of records in the PDU */
      u_int32 sysUpTime; /* Current time in millisecs since router booted */
      u_int32 unix_secs; /* Current seconds since 0000 UTC 1970 */
      u_int32 unix_nsecs; /* Residual nanoseconds since 0000 UTC 1970 */
      u_int32 flow_sequence; /* Seq counter of total flows seen */
      u_int8 engine_type; /* Type of flow switching engine (RP,VIP,etc.) */
      u_int8 engine_id; /* Slot number of the flow switching engine */
      u_int16 reserved;
    }
    """
    header = struct.unpack('!HHIIIIBBH', buf[:SIZE_OF_HEADER])

    # Sanity check - version
    if header[0] != 5:
        print ("Not a NetFlow v5 packet")
        continue

    # Sanity check - count
    if header[1] <= 0:
        print ("Invalid count {0}".format(count))
        continue

    for i in range(0, header[1]):
        base = SIZE_OF_HEADER+(i*SIZE_OF_RECORD)

        """
        /* 48 byte payload */
        struct ftrec_v5 {
          u_int32 srcaddr; /* Source IP Address */
          u_int32 dstaddr; /* Destination IP Address */
          u_int32 nexthop; /* Next hop router's IP Address */
          u_int16 input; /* Input interface index */
          u_int16 output; /* Output interface index */
          u_int32 dPkts; /* Packets sent in Duration */
          u_int32 dOctets; /* Octets sent in Duration. */
          u_int32 First; /* SysUptime at start of flow */
          u_int32 Last; /* and of last packet of flow */
          u_int16 srcport; /* TCP/UDP source port number or equivalent */
          u_int16 dstport; /* TCP/UDP destination port number or equiv */
          u_int8 pad;
          u_int8 tcp_flags; /* Cumulative OR of tcp flags */
          u_int8 prot; /* IP protocol, e.g., 6=TCP, 17=UDP, ... */
          u_int8 tos; /* IP Type-of-Service */
          u_int16 src_as; /* originating AS of source address */
          u_int16 dst_as; /* originating AS of destination address */
          u_int8 src_mask; /* source address prefix mask bits */
          u_int8 dst_mask; /* destination address prefix mask bits */
          u_int16 drops;
        } records[FT_PDU_V5_MAXFLOWS];
        """

        data = struct.unpack('!HHIIIIHHBBBBHHBBH',buf[base+12:base+SIZE_OF_RECORD])

        nfdata = {}

        # Decode the addresses
        nfdata['saddr'] = inet_ntoa(buf[base+0:base+4])
        nfdata['daddr'] = inet_ntoa(buf[base+4:base+8])
        nfdata['nexthop'] = inet_ntoa(buf[base+8:base+12])

        # The rest of the data
        #nfdata['pcount'] = data[2]
        nfdata['bcount'] = data[3]
        #nfdata['stime'] = data[4]
        #nfdata['etime'] = data[5]
        #nfdata['sport'] = data[6]
        #nfdata['dport'] = data[7]

        # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        #nfdata['protocol'] = data[10]

        # Check against internal network mask
        ip_from = nfdata['saddr']
        ip_to = nfdata['daddr']

        from_local = address_in_network(ip_from, LOCAL_MASK)
        to_local = address_in_network(ip_to, LOCAL_MASK)

        if (to_local and not from_local) or (from_local and not to_local):
            if to_local:
                # Downloading
                temp = ip_to
                operation = 0
            else:
                # Uploading
                temp = ip_from
                operation = 1

            # Attempt to find the hostname
            name = temp
            if temp in name_map:
                name = name_map[temp]
            else:
                try:
                    name = socket.gethostbyaddr(temp)[0]
                except socket.herror:
                    pass
                name_map[temp] = name

            # Add the data to the totals
            if not name in name_data:
                name_data[name] = [0, 0]
            name_data[name][operation] += int(data[3])

            # Print the data
            print ("{0} {1}ed {2} bytes".format(name, OPS[operation], nfdata['bcount']))
