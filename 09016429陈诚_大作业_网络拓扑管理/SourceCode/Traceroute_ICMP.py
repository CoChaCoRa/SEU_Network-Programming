#from socket import *
import socket
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 64
TIMEOUT = 2.0
TRIES = 2

def checksum(str_):
    #checksum of the packet
    str_=bytearray(str_)
    csum = 0
    countTo = (len(str_)//2)*2

    for count in range(0,countTo,2):
        thisVal = str_[count+1] * 256 + str_[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff

    if countTo < len(str_):
        csum = csum + str_[-1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    # Make the header
    myChecksum = 0
    myID = os.getpid() & 0xFFFF

    # Make a dummy header with a 0 checksum.
    # struct:Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())

    # Calculate the checksum on the data and the dummy header.
    # Append checksum to the header.
    myChecksum = checksum(header + data)    
    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff
        #Convert 16-bit integers from host to network byte order.
    else:
        myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    packet = header + data
    return packet

def get_route(hostname):
    myAddr = socket.gethostbyname(socket.getfqdn(socket.gethostname()))
    destAddr = socket.gethostbyname(hostname)
    IProute = []
    IProute.append(myAddr)
    print("\nTraceroute to %s (IP:%s)"%(hostname,destAddr))
    print("Protocol: ICMP, %d hops max"%(MAX_HOPS))
    print("sourceAddr: %s"%myAddr)
    timeLeft = TIMEOUT
    for ttl in range(1,MAX_HOPS):
        for _ in range(TRIES):
            
            icmp = socket.getprotobyname("icmp")
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, icmp)
            mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)

                if whatReady[0] == []: # Timeout
                    print ("*    *    * Request timed out.")

                recvPacket, addr = mySocket.recvfrom(1024)
                #print (addr)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                if timeLeft <= 0:
                    timeLeft = 0
                    print ("*    *    * Request timed out.")

            except socket.timeout:
                continue

            else:
                icmpHeader = recvPacket[20:28]
                request_type, _, _, _, _ = struct.unpack("bbHHh", icmpHeader)

                if request_type == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print (" %d   rtt=%.0fms, ip: %s" % (ttl,(timeReceived -t)*1000, addr[0]))
                    IProute.append(addr[0])
                    break
                elif request_type == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print (" %d   rtt=%.0fms, ip: %s" % (ttl,(timeReceived -t)*1000, addr[0]))
                    IProute.append(addr[0])
                    break
                elif request_type == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print (" %d   rtt=%.0fms, ip: %s" % (ttl,(timeReceived -timeSent)*1000, addr[0]))
                    IProute.append(addr[0])

                    return IProute
                else:
                    print ("error")
                    break
            finally:
                mySocket.close()
