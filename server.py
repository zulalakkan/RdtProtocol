import os.path
import socket
import time 
import random as rd
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random

def pad(s):
    #return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
    return s + (16 - len(s) % 16) * bytes([(16 - len(s) % 16)])
def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

# Represents integers from 0-255 in one byte
def toByte(s):
    #return chr(s).encode('utf-8')
    return bytes([s]) 
    #return bytes("\x{:02x}".format(s).encode('utf-8'))


# Returns 0-255 byte to integer
def fromByte(s):
    return ord(s)

def unreliableSend(packet, sock, user, errRate):
    if errRate < rd.randint(0,100):
        sock.sendto(packet, user)

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
user = (HOST, PORT)
status = "Start"

errRate = 10 # Average Error rate of the unreliable channel
TIMEOUT = 5.0001 # Timeout value
N = 1 # Go-back-N N


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    # Create UDP socket
sock.bind(user)
sock.settimeout(TIMEOUT)  

while True:
    print(status)
    # try - except
    if status == 'Start':
        data, user = sock.recvfrom(1024)
        if data[0] == 0:
            status = 'Handshake'
        else:
            continue
    else:
        if status == 'Handshake':
            packetLen = data[1]
            print(data[2:2+packetLen])
            keyIndex = data.find(b'.txtssh-rsa') + 4
            fileName = data[2:keyIndex].decode('utf-8')
            publicKey = data[keyIndex:2+packetLen].decode('utf-8')
            print("fileName: {0}\npublicKey:{1}".format(fileName, publicKey))

            # check for filename 
            if os.path.exists(fileName):
                # sessionKey
                sessionKey = Random.get_random_bytes(32)
                AEScipher = AES.new(sessionKey, AES.MODE_ECB)
                
                # pkt
                pType = toByte(0)
                packet = pType + toByte(len(sessionKey)) + sessionKey
                
                publicKey = RSA.import_key(publicKey)
                rsaEncryptor = PKCS1_OAEP.new(publicKey)
                packet = rsaEncryptor.encrypt(packet)
                # unreliableSend(packet, sock, user, errRate)
                sock.sendto(packet, user)
                print("sessionKey:", sessionKey)
                status = 'Data Transfer'
            else:
                #timeout
                status = 'Start'
                sock.sendto(packet, user)
                continue
 
        elif status == 'Data Transfer':
            # get ack 00
                ack_data, user = sock.recvfrom(1024)
                print("ACK data:",ack_data)
                ack_data = AEScipher.decrypt(pad(ack_data))
                print("ACK data-decrypt:", ack_data)
                packetType = ack_data[0]
                if packetType == 1:
                    print("data transfer ins")
                    seqNum = ack_data[1]
                    if seqNum == 0:
                        lines = readFromFile(fileName)
                    else: 
                        print("wordlala")
                        # tek tek yolla
                else:
                    print("waitin gfor my ack")
                    pass
                # dosya okuma
                # kelimlere bölme
                # tek tek yollama
                # 
                # ack kontrolü
                # go back n oku 
        else:
            exit()