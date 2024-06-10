
SERVER_NAME_LEN = 256
TLS_HEADER_LEN = 5
TLS_HANDSHAKE_CONTENT_TYPE = 0x16
TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01

def parse_tls_header(data, data_len):
    hostname = None
    pos = TLS_HEADER_LEN

    if not data:
        return -3, hostname

    if len(data) < TLS_HEADER_LEN:
        return -1, hostname
    
    if data[0] != TLS_HANDSHAKE_CONTENT_TYPE:
        #print("Request did not begin with TLS handshake")
        return -5, hostname
    
    if data[0] & 0x80 and data[2] == 1:
        print("Received SSL 2.0 Client Hello which can not support SNI.")
        return -2, hostname

    tls_version_major, tls_version_minor = data[1:3]

    if tls_version_major < 3:
        print("Received SSL ", tls_version_major, ".", tls_version_minor, " handshake which can not support SNI.")
        return -2, hostname

    length = (data[3] << 8) + data[4] + TLS_HEADER_LEN
    data_len = min(data_len, length)

    if data_len < length:
        return -1, hostname

    if pos + 1 > data_len or data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
        #print("Not a client hello")
        return -5, hostname

    '''
    Skip past fixed length records:
       1	Handshake Type
       3	Length
       2	Version (again)
       32	Random
       to	Session ID Length
    '''
    pos += 38

    #Session ID
    if pos + 1 > data_len:
        return -5, hostname
    pos += 1 + data[pos]

    #Cipher Suites
    if pos + 2 > data_len:
        return -5, hostname
    pos += 2 + (data[pos] << 8) + data[pos + 1]

    #Compression methods
    if pos + 1 > data_len:
        return -5, hostname
    pos += 1 + data[pos]

    if pos == data_len and tls_version_major == 3 and tls_version_minor == 0:
        print("Received SSL 3.0 handshake without extensions")
        return -2, hostname

    #Extensions (overall size)
    if pos + 2 > data_len:
        return -5, hostname
    pos += 2

    if pos + (data[pos] << 8) + data[pos + 1] > data_len:
        return -5, hostname

    return parse_extensions(data[pos:], data_len - pos)


def parse_extensions(data, data_len):
    pos = 0

    #Parse each 4 bytes for the extension header
    while pos + 4 <= data_len:
        #Extension length
        length = (data[pos + 2] << 8) + data[pos + 3]

        #Check if Server name extension
        #print(data[pos], data[pos+1])
        if data[pos] == 0x00 and data[pos + 1] == 0x00:
            #There can be only one extension of each type, so we break our state and move pos to beginning of the extension here
            if pos + 4 + length > data_len:
                return -5, None
            
            return parse_server_name_extension(data[pos + 4:], length)

        pos += 4 + length #Advance to the next extension header

    #check we ended were we expected to
    if pos != data_len:
        return -5, None
    print("No server name extension")
    return -2, None


def parse_server_name_extension(data, data_len):
    pos = 2 #skip server name list lentgth
    hostname = None

    while pos + 3 < data_len:
        #print("qua")
        length = (data[pos + 1] << 8) + data[pos + 2]

        if pos + 3 + length > data_len:
            return -5, None

        if data[pos] == 0x00: #name type
            hostname = data[pos + 3:pos + 3 + length].decode() #get hostname
            #print("eccoci", hostname)
            if hostname:
                return len(hostname), hostname
            break
        else:
            print("Unknown server name extension name type: ", data[pos])

        pos += 3 + length

    #Check we ended where we expected to
    if pos != data_len:
        return -5, None

    print("fine")
    return -2, hostname

