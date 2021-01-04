import os.path
import socket
import time 
import random as rd
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random

def pad(s):
    return s + (16 - len(s) % 16) * bytes([(16 - len(s) % 16)])
def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

# Represents integers from 0-255 in one byte
def toByte(s):
    return bytes([s])


# Returns 0-255 byte to integer
def fromByte(s):
    return ord(s)

def unreliableSend(packet, sock, user, errRate):
    if errRate < rd.randint(0,100):
        sock.sendto(packet, user)

def readFromFile(fileName):
    lines = []
    targetFile = open(fileName,'r', encoding='utf-8')
    while True:
        line = targetFile.readline() 
        if len(line) == 0:
            break
        lines.append(line)
        print(line)
    return lines

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
user = (HOST, PORT)
status = "Start"

errRate = 10        # Average Error rate of the unreliable channel
TIMEOUT = 0.0001    # Timeout value
N = 5              # Go-back-N N {1, 5, 20, 50, 100}
isTimeout = False


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    # Create UDP socket
sock.bind(user)
sock.settimeout(TIMEOUT)

tick = time.time()
while True:
    print(status)
    try:
        if status == 'Start':
            data, user = sock.recvfrom(1024)
            if data[0] == 0:
                status = 'Handshake'
            else:
                continue
        else:
            if status == 'Handshake':
                packetLen = data[1]
                keyIndex = data.find(b'.txtssh-rsa') + 4
                fileName = data[2:keyIndex].decode('utf-8')
                publicKey = data[keyIndex:2+packetLen].decode('utf-8')
                # print("fileName: {0}\npublicKey:{1}".format(fileName, publicKey))

                if os.path.exists(fileName):                         # check for filename 
                    sessionKey = Random.get_random_bytes(32)         # sessionKey generated
                    AEScipher = AES.new(sessionKey, AES.MODE_ECB)
                    
                    # handshake packet
                    pType = toByte(0)
                    packet = pType + toByte(len(sessionKey)) + sessionKey
                    
                    publicKey = RSA.import_key(publicKey)
                    rsaEncryptor = PKCS1_OAEP.new(publicKey)
                    packet = rsaEncryptor.encrypt(packet)
                    unreliableSend(packet, sock, user, errRate)
                    # print("sessionKey:", sessionKey)
                    status = 'Data Transfer'
                    handshakeAck = True
                else:                                               # filename is not correct, go back to Start state
                    status = 'Start'
                    unreliableSend(packet, sock, user, errRate)
                    continue
    
            elif status == 'Data Transfer':
                if not isTimeout or handshakeAck:                   # if ack is not timeout or waiting for handshake ack
                    ack_data, user = sock.recvfrom(1024)            # then keep waiting for the ack
                    ack_data = AEScipher.decrypt(pad(ack_data))
                    packetType = ack_data[0]
                    if packetType == 1:                             # acknowledgement packet
                        print("ACK seq num:", ack_data[1])
                        ackSeqNum = ack_data[1]
                        if ackSeqNum == 0 and handshakeAck:         # handshake ack is important to start sending data pkts
                            handshakeAck=False
                            lines = readFromFile(fileName)          # read file, get lines
                            seqNum = 0                              # init variables to keep track of the network
                            sendBase = 0
                            index = 0
                        elif ackSeqNum != (sendBase % 256):
                            if ackSeqNum > sendBase % 256 or (sendBase > (255 - N) and ackSeqNum < N ):
                                isTimeout = True
                            continue
                        else:                                       # we have an ack
                            sendBase = sendBase - (sendBase % 256) + ackSeqNum +1 # shift window
                            if index == len(lines) and ackSeqNum == index % 256 - 1:
                                # print("Finish")
                                status = 'Finish'
                                continue
                if not handshakeAck:                                # not waiting for handshake ack
                    if isTimeout:                                   # while waiting for the ack socket timed out
                        index = sendBase                            # go back N
                        seqNum = index % 256
                        isTimeout = False

                    while index < sendBase + N and index < len(lines):     # keep sending
                        payload = lines[index].encode('utf-8')
                        packet = toByte(2) + toByte(len(payload)) + toByte(seqNum)
                        packet += payload
                        packet = AEScipher.encrypt(pad(packet))
                        print("Sent data ", seqNum, payload)
                        unreliableSend(packet, sock, user, errRate)
                        seqNum = (seqNum + 1) % 256
                        index += 1            
            elif status == 'Finish':
                packet = toByte(3) + toByte(seqNum)
                packet = AEScipher.encrypt(pad(packet))
                print("Sent fin ", seqNum)
                unreliableSend(packet, sock, user, errRate)
                break
            else:
                exit()
    except socket.timeout as ex:
        print(ex, status)
        if status == 'Data Transfer':
            isTimeout = True    # timeout in acknowledgements

tock = time.time()
timeElapsed = tock - tick
print("N:", N)
print("Total time: ", timeElapsed)