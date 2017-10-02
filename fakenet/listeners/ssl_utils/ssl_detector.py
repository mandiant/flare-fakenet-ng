import logging

def looks_like_ssl(data):

    size = len(data)

    valid_versions = { 
    'SSLV3'   : 0x300,
    'TLSV1'   : 0x301,
    'TLSV1_1' : 0x302,
    'TLSv1_2' : 0x303
    }

    content_types = {
    'ChangeCipherSpec'  : 0x14,
    'Alert'             : 0x15,
    'Handshake'         : 0x16,
    'Application'       : 0x17,
    'Heartbeat'         : 0x18
    }

    handshake_message_types = {
    'HelloRequest'      : 0x00,
    'ClientHello'       : 0x01,
    'ServerHello'       : 0x02,
    'NewSessionTicket'  : 0x04,
    'Certificate'       : 0x0B,
    'ServerKeyExchange' : 0x0C,
    'CertificateRequest': 0x0D,
    'ServerHelloDone'   : 0x0E,
    'CertificateVerify' : 0x0F,
    'ClientKeyExchange' : 0x10,
    'Finished'          : 0x14
    }

    if size < 10:
        return False

    # check for sslv2 which is deprecated but malware may use it anyway
    if ord(data[0]) == 0x80:
        if ord(data[2]) in handshake_message_types:
            self.logger.info('SSLv2 detected')
            return True
        return False

    elif ord(data[0]) not in content_types.values():
        return False

    elif ord(data[0]) == content_types['Handshake']:
        return ord(data[5]) in handshake_message_types.values()

    ssl_version = ord(data[1]) << 8 | ord(data[2])
    if ssl_version not in valid_versions.values():
        return False
    return True

