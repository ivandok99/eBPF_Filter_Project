import ctypes
import pyroute2
import bpf_maps
import socket
import binascii
import time
import https_sni_parser
from os import getcwd

libbpf = ctypes.CDLL("/usr/lib64/libbpf.so.1.2.2",use_errno=True)
libbpf.bpf_object__open_file.argtypes = [ ctypes.c_char_p, ctypes.c_void_p]
libbpf.bpf_object__open_file.restype = ctypes.c_void_p
libbpf.bpf_map_delete_elem.argtypes = [ctypes.c_int, ctypes.c_void_p]
libbpf.bpf_map_delete_elem.restype = ctypes.c_int
libbpf.bpf_object__next_program.argtypes = [ ctypes.c_void_p, ctypes.c_void_p]
libbpf.bpf_object__next_program.restype = ctypes.c_void_p
libbpf.bpf_program__set_type.argtypes = [ ctypes.c_void_p, ctypes.c_int]
libbpf.bpf_program__set_type.restype = ctypes.c_int
libbpf.bpf_object__load.argtypes = [ ctypes.c_void_p]
libbpf.bpf_object__load.restype = ctypes.c_int
libbpf.bpf_program__fd.argtypes = [ ctypes.c_void_p]
libbpf.bpf_program__fd.restype = ctypes.c_int
libbpf.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
libbpf.bpf_object__find_map_by_name.restype = ctypes.c_void_p
libbpf.bpf_object__find_map_fd_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
libbpf.bpf_object__find_map_fd_by_name.restype = ctypes.c_int

CLEANUP_N_PACKETS = 100
MAX_URL_STRING_LEN = 8162 
MAX_AGE_SECONDS = 30       
BPF_PROG_TYPE_SOCKET_FILTER = ctypes.c_int(1)
BPF_PROG_TYPE_SCHED_CLS = ctypes.c_int(3)
SO_ATTACH_BPF = 50
ETH_P_ALL = 3
ETH_P_IP = 0x0800

blockTls = ["www.google.com","example.com", "yoroi.company"]
blockhttp = { 'www.basilicasanmarco.it':['.jpg','fotolia'], 'yoroi.com':['/']}

# print str until CR+LF
def getFirstLine(s):
    return s.split(b'\r\n')[0].decode()

def getHostHeader(s):
    headers = s.split(b'\r\n')
    for header in headers:
        if (b'Host') in header:
            return header.split(b': ')[1].decode()
    return -1        


# cleanup function
def cleanup():

    for key, value in block_map:
        err = libbpf.bpf_map_delete_elem(bpf_blockMap_fd, ctypes.byref(key))
        print("Error in deleting from blockmap",err) if err!=0 else {}

    current_time = int(time.time())

    for key,value in connections_map:
        try:
            tmstp = connections_map[key]
            if (tmstp == 0):
                connections_map[key] = current_time
            else:
                if (current_time - tmstp> MAX_AGE_SECONDS):
                    print("max age reached", key)
                    err = libbpf.bpf_map_delete_elem(bpf_connections_fd, ctypes.byref(key))
                    if err!=0:
                        raise Exception(err)
        except:
            print("cleanup exception.")
    
    return


filenameFilter = (getcwd() + "/traffic_filter.o").encode('utf-8')
filenameBlocker = (getcwd() + "/blocker_tccls.o").encode('utf-8')

obj = libbpf.bpf_object__open_file(filenameFilter, None)
if obj==None:
    raise Exception("libbpf error in opening traffic-filter")

prog = libbpf.bpf_object__next_program(obj, None)
if prog==None:
    raise Exception("libbpf error in getting http_filter function in bpf object traffic-filter")

err = libbpf.bpf_program__set_type(prog, BPF_PROG_TYPE_SOCKET_FILTER)
if err!=0:
    raise Exception("libbpf error in setting socket filter program type")

err = libbpf.bpf_object__load(obj)
if err!=0:
    raise Exception("libbpf error in loading bpf object traffic-filter")

prog1_fd = libbpf.bpf_program__fd(prog)
if prog1_fd<0:
    raise Exception("libbpf error in getting filter function file descriptor")

bpf_connections_map = libbpf.bpf_object__find_map_by_name(obj, "connections".encode('utf-8'))
if bpf_connections_map==None:
    raise Exception("libbpf error in getting connections map by name")

bpf_connections_fd = libbpf.bpf_object__find_map_fd_by_name(obj, "connections".encode('utf-8'))
if bpf_connections_fd<0:
    raise Exception("libbpf error in getting connections map fd by name") 

connections_map = bpf_maps.BPF_Map.get_map_by_fd(bpf_connections_fd)

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ETH_P_IP)
sock.bind(("eth1",ETH_P_ALL))
sock.setsockopt(socket.SOL_SOCKET,SO_ATTACH_BPF, prog1_fd)
sock.setblocking(True)

obj2 = libbpf.bpf_object__open_file(filenameBlocker, None)
if obj2==None:
    raise Exception("libbpf error in opening blocker-tccls file")

prog2 = libbpf.bpf_object__next_program(obj2, None)
if prog2==None:
    raise Exception("libbpf error in getting blocker function in blocker-tccls")

err=libbpf.bpf_program__set_type(prog2, BPF_PROG_TYPE_SCHED_CLS)
if err!=0:
    raise Exception("libbpf error in setting sched cls type")

err = libbpf.bpf_object__load(obj2)
if err!=0:
    raise Exception("libbpf error in loading blocker-tccls")

prog2_fd = libbpf.bpf_program__fd(prog2)
if prog2_fd<0:
    raise Exception("libbpf error in getting blocker function fd")

bpf_blockMap_fd = libbpf.bpf_object__find_map_fd_by_name(obj2, "blockMap".encode('utf-8'))
if bpf_blockMap_fd<0:
    raise Exception("libbpf error in getting blockMap fd")

block_map = bpf_maps.BPF_Map.get_map_by_fd(bpf_blockMap_fd)

ipr = pyroute2.IPRoute()
ipdb = pyroute2.IPDB(nl=ipr)
idx = ipdb.interfaces["eth1"].index

ipr.tc("add", "clsact", idx)
#ingress traffic filter
ipr.tc("add-filter", "bpf", idx, ":1", fd=prog2_fd, name="blocker", parent= "ffff:fff2", classid=1, direct_action=True)
#egress traffic filter
ipr.tc("add-filter", "bpf", idx, ":1", fd=prog2_fd, name="blocker", parent= "ffff:fff3", classid=1, direct_action=True)


packet_count = 0
crlf = b'\r\n'
crlfx2 = b'\r\n\r\n'

local_dictionary = {}

class Key(ctypes.Structure):
    _fields_ = [("src_ip", ctypes.c_uint),
                ("dst_ip", ctypes.c_uint),
                ("src_port", ctypes.c_ushort),
                ("dst_port", ctypes.c_ushort)]

print("Loading finished")

try:
    while True:
        packet_str = sock.recv(1500) # set packet length to max packet length on the interface
        
        packet_count += 1

        packet_bytearray = bytearray(packet_str)

        ETH_HLEN = 14

        # calculate packet total length
        total_length = packet_bytearray[ETH_HLEN + 2]                 # load MSB
        total_length = total_length << 8                              # shift MSB
        total_length = total_length + packet_bytearray[ETH_HLEN + 3]  # add LSB

        # calculate ip header length
        ip_header_length = packet_bytearray[ETH_HLEN]     # load Byte
        ip_header_length = ip_header_length & 0x0F        # mask bits 0..3
        ip_header_length = ip_header_length << 2          # shift to obtain length

        # retrieve ip source/dest
        ip_src_str = packet_str[ETH_HLEN + 12: ETH_HLEN + 16]  # ip source offset 12..15
        ip_dst_str = packet_str[ETH_HLEN + 16:ETH_HLEN + 20]   # ip dest   offset 16..19

        ip_src = int(binascii.hexlify(ip_src_str), 16)
        ip_dst = int(binascii.hexlify(ip_dst_str), 16)

        # calculate tcp header length
        tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  # load Byte
        tcp_header_length = tcp_header_length & 0xF0    # mask bit 4..7
        tcp_header_length = tcp_header_length >> 2      # SHR 4 ; SHL 2 -> SHR 2

        # retrieve port source/dest
        port_src_str = packet_str[ETH_HLEN + ip_header_length:ETH_HLEN + ip_header_length + 2]
        port_dst_str = packet_str[ETH_HLEN + ip_header_length + 2:ETH_HLEN + ip_header_length + 4]

        port_src = int(binascii.hexlify(port_src_str), 16)
        port_dst = int(binascii.hexlify(port_dst_str), 16)

        # calculate payload offset
        payload_offset = ETH_HLEN + ip_header_length + tcp_header_length

        # payload_string contains only packet payload
        payload_string = packet_str[(payload_offset):(len(packet_bytearray))]
        
        connection_key = Key(ip_src, ip_dst, port_src, port_dst)
       
        '''if block_map[session_key] != None:
            print("trovato")
            err = libbpf.bpf_map_delete_elem(bpf_blockMap_fd, ctypes.byref(session_key))
            print("Error in deleting from blockmap",err) if err!=0 else {}
        '''
        
        if connections_map[connection_key]!=None:
            if port_src == 443 or port_dst == 443:
                length, hostname = https_sni_parser.parse_tls_header(packet_bytearray[payload_offset:], len(packet_bytearray[payload_offset:]))
                if length >= 0:
                    if hostname in blockTls:
                        print("https blocked:", hostname)
                        block_map[connection_key] = ctypes.c_int(0)
                    
                    err = libbpf.bpf_map_delete_elem(bpf_connections_fd, ctypes.byref(connection_key))
                    print("Error in deleting from map",err) if err!=0 else {}
                elif length == -1:
                    local_dictionary[binascii.hexlify(connection_key)] = packet_bytearray[payload_offset:]
                else:
                    if (binascii.hexlify(connection_key) in local_dictionary):
                        new_packet_bytearray = local_dictionary[binascii.hexlify(connection_key)] + packet_bytearray[payload_offset:]
                        length, hostname = https_sni_parser.parse_tls_header(new_packet_bytearray, len(new_packet_bytearray))
                        if length >=0:
                            if hostname in blockTls:
                                print("https blocked:", hostname)
                                block_map[connection_key] = ctypes.c_int(0)
                            try:
                                err = libbpf.bpf_map_delete_elem(bpf_connections_fd, ctypes.byref(connection_key))
                                print("Error in deleting from map",err) if err!=0 else {}
                                del local_dictionary[binascii.hexlify(connection_key)]
                            except:
                                print("Error in deleting from map or dictionary")
                        elif length == -1:
                            if (len(new_packet_bytearray) > MAX_URL_STRING_LEN/2):
                                print("tls header too long")
                                
                                try:
                                    err = libbpf.bpf_map_delete_elem(bpf_connections_fd, ctypes.byref(connection_key))
                                    print("Error in deleting from map",err) if err!=0 else {}
                                    del local_dictionary[binascii.hexlify(connection_key)]
                                except:
                                    print("Error in deleting from map or dict")
                            local_dictionary[binascii.hexlify(connection_key)] = new_packet_bytearray
                        else:
                            print("not a desired TLS handshake")
                            try:
                                err = libbpf.bpf_map_delete_elem(bpf_connections_fd, ctypes.byref(connection_key))
                                print("Error in deleting from map",err) if err!=0 else {}
                                del local_dictionary[binascii.hexlify(connection_key)]
                            except:
                                print("Error in deleting from map or dict")    
                    else:
                        err = libbpf.bpf_map_delete_elem(bpf_connections_fd, ctypes.byref(connection_key))
                        print("Error in deleting from map",err) if err!=0 else {}

            elif port_src == 80 or port_dst == 80:
                if ((payload_string[:3] == b'GET') or (payload_string[:4] == b'POST')
                        or (payload_string[:4] == b'HTTP') or (payload_string[:3] == b'PUT')
                        or (payload_string[:6] == b'DELETE') or (payload_string[:4] == b'HEAD')):
                    # match: HTTP GET/POST packet found
                    host = getHostHeader(payload_string)
                    if (crlf in payload_string and host!=-1):
                        # url entirely contained in first packet -> print it all
                        if host in blockhttp:
                            firstline = getFirstLine(payload_string).split(' ')
                            for path in blockhttp[host]:
                                if path in firstline[1]:
                                    print("http blocked:",host, end=" ")
                                    print(firstline[0] + " " + firstline[1])
                                    block_map[connection_key] = ctypes.c_int(0)
                        err = libbpf.bpf_map_delete_elem(bpf_connections_fd, ctypes.byref(connection_key))
                        print("Error in deleting from map",err) if err!=0 else {}
                    else:
                        local_dictionary[binascii.hexlify(connection_key)] = payload_string
                else:
                    # NO match: HTTP GET/POST  NOT found
                    if (binascii.hexlify(connection_key) in local_dictionary):
                        # first part of the HTTP GET/POST url is already present in
                        prev_payload_string = local_dictionary[binascii.hexlify(connection_key)]
                        # looking for CR+LF in current packet.
                        host = getHostHeader(payload_string)
                        if (crlf in payload_string and host!=-1):
                            # last packet. containing last part of HTTP GET/POST
                            prev_payload_string += payload_string
                            if host in blockhttp:
                                firstline = getFirstLine(payload_string).split(' ')
                                print(host)
                                for path in blockhttp[host]:
                                    if path in firstline[1]:
                                        print(firstline[0] + " " + firstline[1])
                                        block_map[connection_key] = ctypes.c_int(0)
                            try:
                                err= libbpf.bpf_map_delete_elem(bpf_connections_fd, ctypes.byref(connection_key))
                                print("Error in deleting from map",err) if err!=0 else {}
                                del local_dictionary[binascii.hexlify(connection_key)]
                            except:
                                print("error deleting from map or dictionary")
                        else:
                            # NOT last packet.
                            prev_payload_string += payload_string
                            # check if not size exceeding
                            if (len(prev_payload_string) > MAX_URL_STRING_LEN or crlfx2 in prev_payload_string):
                                print("url too long or host header not found")
                                try:
                                    err = libbpf.bpf_map_delete_elem(bpf_connections_fd, ctypes.byref(connection_key))
                                    print("Error in deleting from map",err) if err!=0 else {}
                                    del local_dictionary[binascii.hexlify(connection_key)]
                                except:
                                    print("error deleting from map or dict")
                            # update dictionary
                            local_dictionary[binascii.hexlify(connection_key)] = prev_payload_string
                    else:
                        libbpf.bpf_map_delete_elem(bpf_connections_fd, ctypes.byref(connection_key))
                        print("Error in deleting from map",err) if err!=0 else {}
            else:
                print("Error in is_tls")
        else:
            print("Packet not in any session")
        # check if dirty entry are present in bpf_sessions
        if (((packet_count) % CLEANUP_N_PACKETS) == 0):
            cleanup()
except KeyboardInterrupt:
    ipr.tc("del","clsact",idx)
    sock.close()
    ipdb.release()
    print("\nRimosso")

