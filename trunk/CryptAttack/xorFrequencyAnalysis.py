'''
This file implements an attack on stream ciphers where there is no known text but it is suspected
that the keystream is repeating. The core function is xorAnalysis. It will take an array of bytes
suspected to have been encrypted with the same byte of keystream and analyze them using english
language text frequency.

It will return the array of bytes with it's best guess at their decryption
'''

from numpy import float64,zeros

'''A class that will analyze a string or list of characters and give back an error index indicating
how likely it is that they are english text based on frequency. Lower the more it conforms to
english letter frequency

fAnalysis = frequency_analysis('asdfasjdlkjashflueauifhaifaadnvfnuvlaifdnviuairnvagyhtadhgurahlfgiuauieafleaeuilfafhadksfnadjknadfjkgl')
print fAnalysis.error()
>>>2.35048111934

fAnalysis = frequency_analysis('Iliketoeatcheesebaconandburgerseverysingledayoflifeforeverysinglemealevermyfavoritetypeofcheeseisswiss')
print fAnalysis.error()
>>>0.971711816259
'''
class frequency_analysis:
    def __init__(self, ciphertext):
        self.cor=[0.64297,0.11746,0.21902,0.33483,1.00000,0.17541,
        0.15864,0.47977,0.54842,0.01205,0.06078,0.31688,0.18942,
        0.53133,0.59101,0.15187,0.00748,0.47134,0.49811,0.71296,
        0.21713,0.07700,0.18580,0.01181,0.15541,0.00583]
        self.ciphertext=ciphertext.lower()
        self.freq()

    def freq(self):
        self.arr=zeros(26,float64)
        for l in self.ciphertext:
            x=ord(l)
            if (x>=97 and x<=122):
                self.arr[x-97]+=1.0
        self.arr/=max(self.arr)

    def error(self):
        e=0
        for i in range(0,len(self.arr)):
            e+=abs(self.arr[i]-self.cor[i])**2
        return e

def findMinIdx(arr):
    curIdx = 0
    curMin = 99999999999999999999
    for i in range(0,len(arr)):
        if(arr[i] != 'nan' and arr[i] < curMin):
            curMin = arr[i]
            curIdx = i
    return curIdx
'''
Perform the XOR analysis on the array of bytes.
They should have been encrypted with the same byte of keystream and be
suspected to contain mostly letters from english text, any non alpha characters are 
effecively ignored in the analysis, we will still decrypt them but they don't factor into
the frequency analysis
'''
'''
E.G.
Some random english text encrypted with a repeating nonce
ef2a26347932385d857d226bb86bb762 -> helloworld
ee2323337324275f857c2c6bb86bb762 -> ilikeapples
e623263c773c365f99753a65b86bb762 -> alldayapples
e53d2b367430335c9b6c3373b179a562 -> branbudsruletoo
ee2933376320365b9d76307ba478b362 -> ifyoueattoomany
f3272f366f2a224385713e60a06bb762 -> thenyoullhave
e22e3e3178222340886a2b6bb86bb762 -> eatingtoast

Lets take the first byte from each piece of ciphertext and try to crack it

bytes = [0xef,0xee,0xe6,0xe5,0xee,0xf3,0xe2]
print xorAnalysis(bytes)
>>>['H', 'I', 'A', 'B', 'I', 'T', 'E']

SUCCESS, it got the first letter from each word right, can work with small amounts of input
even if it fails on some bytes in a long string, you'll still get a decent rate and can 
probably fill in the blanks!
'''
def xorAnalysis(bytes):
    testByte = bytes[0]
    scores = [0]*94

    for l in range(33,127):
        keyStream = testByte ^ l
        testStr = ''
        for i in range(1,len(bytes)):
            testStr += chr(bytes[i] ^ keyStream)
            fAnalysis = frequency_analysis(testStr)
        scores[l-33] = fAnalysis.error()
        
    bestGuess = findMinIdx(scores)+33
    keyStream = bestGuess ^ testByte
    
    chars = [0]*len(bytes)
    for i in range(0,len(bytes)):
        chars[i] = chr(bytes[i] ^ keyStream)
        
    return chars
