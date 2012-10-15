from Crypto.Cipher import AES
import binascii,os
BLOCK_SIZE = 16
PADDING = '}'

def getRandomIv():
    return os.urandom(16)

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

class CtrCounter(object):
    def __init__(self, iv=None, wrap=None):
        if iv is None: iv = os.urandom(16)
        iv = binascii.hexlify(iv)
        self.iv = int(iv, 16)
        self.count = 0
        self.wrap=wrap
    def counter(self):
        if (self.wrap is not None and self.count == self.wrap):
            self.iv = self.iv - self.wrap
            self.count = 0
        self.iv = self.iv+1
        self.count = self.count + 1
        print binascii.unhexlify(hex(self.iv)[2:34])
        return binascii.unhexlify(hex(self.iv)[2:34])
        

def encrypt(data,method,iv,key,wrap=None):
    if(method == 'CBC'):
        cipher = AES.new(key,AES.MODE_CBC,iv)
    elif(method == 'CTR'):
        ctrCounter = CtrCounter(iv,wrap)
        cipher = AES.new(key,AES.MODE_CTR,counter=ctrCounter.counter)
    else:
        cipher = AES.new(key,AES.MODE_ECB)
    data = pad(data)
    return binascii.hexlify(cipher.encrypt(data))

def decrypt(data,method,iv,key,wrap=None):
    if(method == 'CBC'):
        cipher = AES.new(key,AES.MODE_CBC,iv)
    elif(method == 'CTR'):
        ctrCounter = CtrCounter(iv,wrap)
        cipher = AES.new(key,AES.MODE_CTR,counter=ctrCounter.counter)
    else:
        cipher = AES.new(key,AES.MODE_ECB)
    dataBin = binascii.unhexlify(data)
    return cipher.decrypt(dataBin)
        
        
    