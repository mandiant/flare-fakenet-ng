
def hexdump(data):
    
    print 'Printing Raw'
    for d in data:
        print '%02x ' % ord(d),
    print ''

