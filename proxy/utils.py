import socket
import re

def dump_hex(s):
    rvalue = ""
    offset = 0
    step = 0x10
    
    for x in range(0, len(s), step):
        rvalue += "%08X  " % x
        binary_str = s[x:x+step]
        hex_str = ""
        ascii_str = ""
        for y in range(0, len(binary_str)):
            das_byte = ord(binary_str[y])
            
            if(y == 8):
                hex_str += " "
                ascii_str += " "
  
            hex_str += "%02X " % das_byte

            if(das_byte >= 0x7F) or (das_byte < 0x20):
                ascii_str += "."
            else:
                ascii_str += binary_str[y]
                
        rvalue += hex_str.ljust(50)
        rvalue += "%s" % ascii_str
        rvalue += "\n"
        
    return rvalue

def ror(n, r, sz=32):
	mask = (1 << sz) - 1
	
	r = r % sz
	
	if r == 0:
		return n
	
	tmp = n >> r
	tmp |= n << (sz - r)
	
	return (tmp & mask)

def rol(n, r, sz=32):
	return ror(n, r*-1, sz)

def xor_string(key, s):
	rvalue = ""
	
	for x in range(0, len(s)):
		rvalue += chr(ord(s[x]) ^ ord(key[x % len(key)]))
	return rvalue

def HTTP_parse_hdr(s):
    hdrs = {}
    
    http_hdr = s
    content = ""
    
    eoh = s.find("\r\n\r\n")
    if(eoh > 0):
        http_hdr = s[:eoh]
        content = s[eoh+4:]
    
    http_lines = http_hdr.split("\r\n")
    
    if len(http_lines) > 0:
        re_request = re.match(r"(\S+) (\S+) HTTP/([0-9\.]{3})", http_lines[0])
        
        if re_request == None:
            #log.debug("Failed to parse HTTP request: %s" % http_lines[0])
            return {},""
        hdrs["HTTP_type"] = re_request.group(1).upper()
        hdrs["HTTP_uri"] = re_request.group(2)
        hdrs["HTTP_ver"] = re_request.group(3)
        hdrs["HTTP_hdr"] = http_hdr
        #log.info(http_lines[0])

        for l in http_lines[1:]:
            #log.info(l)
            field,sep,value = l.partition(":")
            hdrs[field.lower()] = value.strip()
        
    return hdrs,content
    
def TCP_client(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    try:
        sock.sendall(message)
        response = sock.recv(1024)
        print "Received: {}".format(response)
    finally:
        sock.close()

        
def UDP_client(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((ip, port))
    try:
        sock.sendto(message + "\n", (ip, port))

        response = sock.recv(1024)
        print "Received: {}".format(response)
    finally:
        sock.close()