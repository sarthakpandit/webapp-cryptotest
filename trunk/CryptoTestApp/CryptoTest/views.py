# Create your views here.
from django.http import HttpResponse
from django.template import Context, loader
from CryptoTest.utils import getRandomIv
from CryptoTest.utils import encrypt
from CryptoTest.utils import decrypt
import binascii

defaultIv = b'16BYTESOFPADDING'
defaultKey = b'THISISBESTKEYEVA'

def encryptData(request):
    params = request.GET
    if 'data' in params:
        data = params['data']
    else:
        template = loader.get_template('CryptoTest/helpenc.xhtml')
        context = Context({})
        return HttpResponse(template.render(context))
    
    #Supports ECB or CBC
    if 'mode' in params:
        method = params['mode']
        if(method != 'CBC' and method != 'ECB' and method != 'CTR'):
            method = 'ECB'
    else:
        method = 'ECB'
        
    #Can be static, random, or given as the param in HEX
    if 'IV' in params:
        IV = params['IV']
        if (IV == 'static'):
            IV = defaultIv
        elif (IV == 'random'):
            IV = getRandomIv() 
    else:
        IV = binascii.unhexlify(params['IV'])
        IV = defaultIv
        
    #Optional AES key can be specified in HEX
    if 'secretKey' in params:
        secretKey = binascii.unhexlify(params['secretKey'])
    else:
        secretKey = defaultKey
  
    if 'pre' in params:
        data = params['pre']+data
        
    if 'post' in params:
        data = data+params['post']
        
    #Specify a number for the CTR counter to wrap at
    if 'wrap' in params:
        wrap = int(params['wrap'])
    else:
        wrap = None
       
    return HttpResponse(encrypt(data,method,IV,secretKey,wrap)+"\n")

def decryptData(request):
    params = request.GET
    if 'data' in params:
        data = params['data']
    else:
        template = loader.get_template('CryptoTest/helpdec.xhtml')
        context = Context({})
        return HttpResponse(template.render(context))
    
    #Supports ECB, CBC, CTR
    if 'mode' in params:
        method = params['mode']
        if(method != 'CBC' and method != 'ECB' and method != 'CTR'):
            method = 'ECB'
    else:
        method = 'ECB'
        
    #Can be static, random, or given as the param in HEX
    if 'IV' in params:
        IV = binascii.unhexlify(params['IV'])
        if (IV == 'static'):
            IV = defaultIv
        elif (IV == 'random'):
            IV = getRandomIv() 
    else:
        IV = defaultIv
        
    #Optional AES key can be specified in HEX
    if 'secretKey' in params:
        secretKey = binascii.unhexlify(params['secretKey'])
    else:
        secretKey = defaultKey
  
    #Specify a number for the CTR counter to wrap at
    if 'wrap' in params:
        wrap = int(params['wrap'])
    else:
        wrap = None
  
    return HttpResponse(decrypt(data,method,IV,secretKey,wrap)+"\n")
