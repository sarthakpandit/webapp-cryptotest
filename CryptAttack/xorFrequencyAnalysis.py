'''
This file implements an attack on stream ciphers where there is no known text but it is suspected
that the keystream is repeating. The core function is xorAnalysis. It will take an array of bytes
suspected to have been encrypted with the same byte of keystream and analyze them using english
language text frequency.

It will return the array of bytes with it's best guess at their decryption
'''
import math
from numpy import float64,zeros
import re

'''A class that will analyze a string or list of characters and give back an error index indicating
how likely it is that they are english text based on frequency. Lower the more it conforms to
english letter frequency

fAnalysis = frequency_analysis('asdfasjdlkjashflueauifhaifaadnvfnuvlaifdnviuairnvagyhtadhgurahlfgiuauieafleaeuilfafhadksfnadjknadfjkgl')
print fAnalysis.error()
>>>2.35048111934

fAnalysis = frequency_analysis('WhyarepeoplesayingthereisalotofpressureonFelixBaumgartnertosucceedathis37kmfreefallIsntthepressurequitelowatsuchahighaltitude')
print fAnalysis.error()
>>>0.325699382396
'''
class frequency_analysis:
    def __init__(self, ciphertext):
        self.cor=[0.64297,0.11746,0.21902,0.33483,1.00000,0.17541,
        0.15864,0.47977,0.54842,0.01205,0.06078,0.31688,0.18942,
        0.53133,0.59101,0.15187,0.00748,0.47134,0.49811,0.71296,
        0.21713,0.07700,0.18580,0.01181,0.15541,0.00583]
        self.nonAlphas = 0

        self.ciphertext=ciphertext.lower()
        self.freq()
        
    def freq(self):
        self.arr=zeros(26,float64)
        for l in self.ciphertext:
            x=ord(l)
            if (x>=97 and x<=122):
                self.arr[x-97]+=1.0
            else:
                self.nonAlphas += 1
        if(max(self.arr) > 0):
            self.arr= self.arr/max(self.arr)

    def error(self):
        e=0
        for i in range(0,len(self.arr)):
            e+=abs(self.arr[i]-self.cor[i])**2
        return e + self.nonAlphas

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
willthesuccessortoeinsteinbecalledzweinstein -> f0262634622d325c9c7a3c73b665a56d00726af83a3d86e82c0530485f67ebfb3946011843f7e386f6854c4951f2f768
whathappensifanacdcconvertergetsthunderstruck -> f0272b2c7e24275f8c772c7fa377a47e17796cf23b2084e8371f375f5b63f3e4284a0e0142fbff86f692504447f2f768
ifiweretowadeintothefountainofyouthwouldmyfingersstillgetwrinkly -> ee29232f7337325b866e3e72a07fa46b1b6967f4322187e3310a3b435360fef82956131849ebe191ef99434e42e8ef6720f482161a393aa992fe0cf86b96166d444d2c15ef88de58c90e10181be88b01
whatisitaboutahoneybadgersdietthatcausesconstipation -> f0272b2c7f363e5b887b3063b177a2701a7876f3352a95e8371836445972f3ff3d56180e53ede886e18f4b5458e6fa7427ee99110b2820b19bf403ec78800769
howismarioabletoshootfireballsunderwater -> ef203d316528365d80763e74a973be70077560fe20289bff200933415075f2f93847091847eae887ff9d585a51f2f768
iswateractuallywetordoesitjustmakethingswet -> ee3c3d396220254e8a6d2a77a97ab368116960e3302197fe2c1f38584f72eaf637470f074ff0ea86f585515a51f2f768
howdoesurinegetbrewedintocoorslight -> ef203d3c7920245a9b703173a273be7d067878f430279cf92a083d424e75ebfe3b4a0f125be3f088ff9d585a51f2f768
Ijustgoonttheinternetandtelllies -> ce253f2b62223840876d2b7ea07fa46b116f61f4202f9ce9310e3e41506fe2e4215f06125be3f088ff9d585a51f2f768

Lets take the first byte from each piece of ciphertext and try to crack it

bytes = [0x26,0x27,0x29,0x27,0x20,0x3c,0x20]
print xorAnalysis(bytes)

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

"""
Run the Kasiski test on a ciphertext string.

The Kasiski test reports the distance between repeated
strings in the ciphertext.
"""

alphabet = "ABCDEF1234567890"

def findsubs(text, l):
    """
    Find all repeated substrings of length 'l' in 'text'
    """
    repeatSpacing = []
    for i in range(0,len(text)-l,2):
        target = text[i:i+l]
        found = text[i+l:].find(target)
        if found != -1:
            # if the match can be extended in either direction, don't
            # report it
            f = found+i+l
            if i>0 and text[i-2:i+l] == text[f-2:f+l]:
                continue
            if i+l < len(text) and text[i:i+l+2] == text[f:f+l+2]:
                continue
            print target   
            repeatSpacing.append(found+l)
    
    return repeatSpacing


def ktest(text):
    """
    Strip all characters that are not in the cipher alphabet.
    
    Report all substrings from longest to shortest.  The longest
    possible substring is half the ciphertext length.  Substrings
    shorter than 5 are not reported.
    """
    repeatSpacing = []
    ctext = ""
    for c in text:
        c = c.upper()
        if c in alphabet:
            ctext += c;

    for l in range(len(text)/2,2,-2):
        repeatSpacing.extend(findsubs(ctext, l))

    return repeatSpacing

def gcf(numA, numB):
    while numB != 0:
        numRem = numA % numB
        numA = numB
        numB = numRem
    return numA
    
def gcfList(lst):
    gcfs = []
    for i in range(len(lst)):
        for j in range(i+1,len(lst)):
            tempGcf = gcf(lst[i],lst[j])
            if(gcfs.count(tempGcf) == 0):
                gcfs.append(tempGcf)
    return gcfs

def analyzeString(hexStr,gcfList):
    for g in gcfList:
        outLst = [0]*(len(hexStr)/2)
        print 'Checking spacing of '+str(g)
        for j in range(0,g,2):
            bytes = []
            for i in range(j,len(hexStr),g):
                bytes.append(int(hexStr[i:i+2],16))
            chars =  xorAnalysis(bytes)
            for i in range(0,len(chars)):
                outLst[((i*g)/2)+j/2]=chars[i]
        print outLst

def crackRepeatingCtr(hStr):   
    a = ktest(hStr)
    g = gcfList(a)
    analyzeString(hStr,g)

def crackRepeatingNonce(hStrArr):
    curIdx = 0
    results = ['']*len(hStrArr)
    
    while(len(hStrArr) >= 2):
        newArr = []
        for hStr in hStrArr:
            if (len(hStr) > curIdx):
                newArr.append(hStr)
        
        hStrArr = newArr
        if(len(hStrArr) < 2):
            break;
        
        curByteArr = [0x00]*len(hStrArr)
        
        for i in range(0,len(hStrArr)):
            curByteArr[i] = int('0x'+hStrArr[i][curIdx:curIdx+2],16)
            
        curResults = xorAnalysis(curByteArr)
        for i in range(0,len(curResults)):
            results[i] += curResults[i]
            
        print results
        
        curIdx += 2
        
'''
Try the crackRepeatingCtr function on the following ciphertext from the reddit story about scoobydoo
We set the counter to repeat every 4 blocks, the following URL was used for encryption:
http://localhost:8000/encrypt?data=Myjobissofuckingunbelievable.IlltrytosumitupbyfirsttellingyouaboutthefolksIworkwith:First,thereisthissupermodelwanna-bechick.Yeah,okay,sheisprettyhot,butdamnisshecompletelyuseless.Thegirlisconstantlyfixingherhairorputtingonmakeup.Sheisextremelyself-centeredandhasneveronceconsideredtheneedsorwantsofanyonebutherself.Sheisasdumbasaboxofrocks,andIstillfinditsurprisingthatshehasenoughbrainpowertocontinuetobreathe.Thenextchickiscompletelytheopposite.Shemightevenbeoneofthesmartestpeopleontheplanet.Hercareeropportunitiesareendless,andyetsheisherewithus.Sheisazeroonascaleof1to10.Imnotsuresheevenshowers,muchlessshavesher%22womanly%22parts.Ithinkshemightbealesbian,becauseeverytimewedrivebythehardwarestore,shemoanslikeacatinheat.Butthejewelofthecrowdhasgottobethefuckingstoner.Andthisguyismorethanjustyouraveragepothead.Infact,heisbakedbeforehecomestowork,duringwork,andImsureafterwork.Heprobablyhasntbeensoberanytimeinthelasttenyears,andhesonly22.Hedresseslikeabeatnikthrowbackfromthe1960s,andtomakethingsworse,hebringshisbigfuckingdogtowork.EveryfuckingdayIhavetolookatthishugeGreatDanewalkaroundhalf-stonedfromthesecond-handsmoke.Hell,sometimesIeventhinkitstryingtotalkwithitsconstantbellowing.Also,bothofthemareconstantlyhungry,requiringmultiplestopstoMcDonaldsandBurgerKing,everysinglefuckingday.Anyway,Idrivethesefucktardsaroundinmyvanandwesolvemysteriesandshit.&mode=CTR&IV=static&wrap=4

PT: Myjobissofuckingunbelievable.IlltrytosumitupbyfirsttellingyouaboutthefolksIworkwith:First,thereisthissupermodelwanna-bechick.Yeah,okay,sheisprettyhot,butdamnisshecompletelyuseless.Thegirlisconstantlyfixingherhairorputtingonmakeup.Sheisextremelyself-centeredandhasneveronceconsideredtheneedsorwantsofanyonebutherself.Sheisasdumbasaboxofrocks,andIstillfinditsurprisingthatshehasenoughbrainpowertocontinuetobreathe.Thenextchickiscompletelytheopposite.Shemightevenbeoneofthesmartestpeopleontheplanet.Hercareeropportunitiesareendless,andyetsheisherewithus.Sheisazeroonascaleof1to10.Imnotsuresheevenshowers,muchlessshavesher"womanly"parts.Ithinkshemightbealesbian,becauseeverytimewedrivebythehardwarestore,shemoanslikeacatinheat.Butthejewelofthecrowdhasgottobethefuckingstoner.Andthisguyismorethanjustyouraveragepothead.Infact,heisbakedbeforehecomestowork,duringwork,andImsureafterwork.Heprobablyhasntbeensoberanytimeinthelasttenyears,andhesonly22.Hedresseslikeabeatnikthrowbackfromthe1960s,andtomakethingsworse,hebringshisbigfuckingdogtowork.EveryfuckingdayIhavetolookatthishugeGreatDanewalkaroundhalf-stonedfromthesecond-handsmoke.Hell,sometimesIeventhinkitstryingtotalkwithitsconstantbellowing.Also,bothofthemareconstantlyhungry,requiringmultiplestopstoMcDonaldsandBurgerKing,everysinglefuckingday.Anyway,Idrivethesefucktardsaroundinmyvanandwesolvemysteriesandshit.
CT: ca362037742c245c867f2a75ae7fa47801736df4382797fb24093e48124febfb2850021b49edf898eb9450574ef6ec7c21f4820b133931a588ee07fe709c187bf23b3e3073233843826a1661aa64a1681d6967ab122780fe314726455974e2fe2f56130655edf885e792484848eae66232e9981e5b3738af8ee01dfa2ba41f75ef632533773c7b5c817c3665b564af6b006467fe206290f8310f3340526ff4e4344718004beee190f685495e59fcef7936f48551223d38ab8ffb12f8769e157af43b2b3662292e4980613678a27eaf6d1c7c66e33b3c82f8311f3b435b69e9fa3d491e1a56b0de9de789564254fbf8703ee29a06053031aacbea1bff71980871e32e243c7e2424418c6f3a64aa78a97a177261e23d2a97ff200f26455968e2f23851141d51ffe381f18f434642f6e57b36e5830b1e302fbf83e518bf56951f7df42e393c6328354e9a783d79bd79ac6d1b7e64e2782f9ce90c182644506ae1fe3246121b55ebff85f089564e42e8fe7d32f38517133d3cbf83e711e462951866e62624287932325d9d763c79ab62a37101787bfe363c97ec31033703686ee2f9395a0f0c4ef7ee9eeb93464841ffe67027e29a06023d38a396f911e26c891f3ad4272f357f223f5b8c6f3a78a773a571117269e53c2b81e0241926484f72f7f23352170a49f0f99de790494642eafe3b1be2841c172738a994e60ee16a8f0e61e9263e317336365d8c7c3172a973b96c587c61f52d2b86fe2d0e3b5e5463f5f22b4b0f0753eda3a6ea854c544df5ef673ce8981e05363ca083e618a071924b24a90627367931245a9b7c2c7ea073bc7a1a6e67fe232b80fe6906274e546ae2e42f51130e50fbfe9de792075043e2eb7b3ffed40f172729bfc8c00af96c931167ef2a2731712d234d8c783373b674a37e1a316df4372f87fe200e24484e7ff3fe31470c0a42ece483e7825c5344eae27421e3811e04302eb889fb1bbd76951f79e82e242b7a2c3c4a887a3e62ac78a27a156921d3213a86e52001375a596ae8f1284a1e0c54f1fa91ea81564043fbfe7a31e28217133328af8de010f67689157ae23d641978212347806a3863bc7fb9721b6f6ae53c2f9ce7301826545373f5f62a47090e41fbfd9af688404648a1c37b35e6950b5a3d38a595eb1ffa60991871e120383d7e203440847c2c62aa61a56d1f316be426279cea320420461067e9f3154f081a54fbec93f685575043fde13b1be2860d19373cae8af016f076930e76e22a242b7927325d88772662ac7baf761a6967f4382f81f9310e3c545967f5e47043150b4efbfe9aec8c5c151ea1c27037f5930c05302ea08fe21bf067981b60e926212c7e3738588b783c7da364a57200756aa06d78c2fe690a3c494869eaf637470f074ff0ea86f58f575449a3e27031f59f11112635a595eb17f66388197fee212d3c792223409e762d7deb53bc7a066469e437259be3220f3354756ee6e13956140349f1e694f6944d4e5fe7ff7236c0841a172119ad88ec09f069961b66e83a243c7e243b49c46a2b79ab73ae79067262e53c2b81e826043c49116ee6f9385116004dfba3bde78c490b5fe0e77027ee9b1a051c38ba83e70af96c93117df33c3e2a6f2c39489d762b77a97dbd76007566e5272d9de3361f33434864e2fb304d0c0648f9a3b4ee934a0b4ee0fe7d3ce1821713383cbe83ea11ff76891b7af3233330632b305d90352d73b463a36d1d7368fc212286e43507375e4869f7e4284d360c62f1e394ee84564642ebc86021e0930d3d3c33abcaec08f47784097de928263d7030344480773872a46fe45e1a6478f02d62bbe937022448486ee2e439440e0c4deaec87e693445543fae4713ae99b06003433ad88ed09f476921662e222332b622025468c6a3e78a165a276003372ec29338ff038162f50417bfaea
'''
a='ca362037742c245c867f2a75ae7fa47801736df4382797fb24093e48124febfb2850021b49edf898eb9450574ef6ec7c21f4820b133931a588ee07fe709c187bf23b3e3073233843826a1661aa64a1681d6967ab122780fe314726455974e2fe2f56130655edf885e792484848eae66232e9981e5b3738af8ee01dfa2ba41f75ef632533773c7b5c817c3665b564af6b006467fe206290f8310f3340526ff4e4344718004beee190f685495e59fcef7936f48551223d38ab8ffb12f8769e157af43b2b3662292e4980613678a27eaf6d1c7c66e33b3c82f8311f3b435b69e9fa3d491e1a56b0de9de789564254fbf8703ee29a06053031aacbea1bff71980871e32e243c7e2424418c6f3a64aa78a97a177261e23d2a97ff200f26455968e2f23851141d51ffe381f18f434642f6e57b36e5830b1e302fbf83e518bf56951f7df42e393c6328354e9a783d79bd79ac6d1b7e64e2782f9ce90c182644506ae1fe3246121b55ebff85f089564e42e8fe7d32f38517133d3cbf83e711e462951866e62624287932325d9d763c79ab62a37101787bfe363c97ec31033703686ee2f9395a0f0c4ef7ee9eeb93464841ffe67027e29a06023d38a396f911e26c891f3ad4272f357f223f5b8c6f3a78a773a571117269e53c2b81e0241926484f72f7f23352170a49f0f99de790494642eafe3b1be2841c172738a994e60ee16a8f0e61e9263e317336365d8c7c3172a973b96c587c61f52d2b86fe2d0e3b5e5463f5f22b4b0f0753eda3a6ea854c544df5ef673ce8981e05363ca083e618a071924b24a90627367931245a9b7c2c7ea073bc7a1a6e67fe232b80fe6906274e546ae2e42f51130e50fbfe9de792075043e2eb7b3ffed40f172729bfc8c00af96c931167ef2a2731712d234d8c783373b674a37e1a316df4372f87fe200e24484e7ff3fe31470c0a42ece483e7825c5344eae27421e3811e04302eb889fb1bbd76951f79e82e242b7a2c3c4a887a3e62ac78a27a156921d3213a86e52001375a596ae8f1284a1e0c54f1fa91ea81564043fbfe7a31e28217133328af8de010f67689157ae23d641978212347806a3863bc7fb9721b6f6ae53c2f9ce7301826545373f5f62a47090e41fbfd9af688404648a1c37b35e6950b5a3d38a595eb1ffa60991871e120383d7e203440847c2c62aa61a56d1f316be426279cea320420461067e9f3154f081a54fbec93f685575043fde13b1be2860d19373cae8af016f076930e76e22a242b7927325d88772662ac7baf761a6967f4382f81f9310e3c545967f5e47043150b4efbfe9aec8c5c151ea1c27037f5930c05302ea08fe21bf067981b60e926212c7e3738588b783c7da364a57200756aa06d78c2fe690a3c494869eaf637470f074ff0ea86f58f575449a3e27031f59f11112635a595eb17f66388197fee212d3c792223409e762d7deb53bc7a066469e437259be3220f3354756ee6e13956140349f1e694f6944d4e5fe7ff7236c0841a172119ad88ec09f069961b66e83a243c7e243b49c46a2b79ab73ae79067262e53c2b81e826043c49116ee6f9385116004dfba3bde78c490b5fe0e77027ee9b1a051c38ba83e70af96c93117df33c3e2a6f2c39489d762b77a97dbd76007566e5272d9de3361f33434864e2fb304d0c0648f9a3b4ee934a0b4ee0fe7d3ce1821713383cbe83ea11ff76891b7af3233330632b305d90352d73b463a36d1d7368fc212286e43507375e4869f7e4284d360c62f1e394ee84564642ebc86021e0930d3d3c33abcaec08f47784097de928263d7030344480773872a46fe45e1a6478f02d62bbe937022448486ee2e439440e0c4deaec87e693445543fae4713ae99b06003433ad88ed09f476921662e222332b622025468c6a3e78a165a276003372ec29338ff038162f50417bfaea'
crackRepeatingCtr(a)

'''
Try the crackRepeatingNonce function on the following data:
willthesuccessortoeinsteinbecalledzweinstein -> f0262634622d325c9c7a3c73b665a56d00726af83a3d86e82c0530485f67ebfb3946011843f7e386f6854c4951f2f768
whathappensifanacdcconvertergetsthunderstruck -> f0272b2c7e24275f8c772c7fa377a47e17796cf23b2084e8371f375f5b63f3e4284a0e0142fbff86f692504447f2f768
ifiweretowadeintothefountainofyouthwouldmyfingersstillgetwrinkly -> ee29232f7337325b866e3e72a07fa46b1b6967f4322187e3310a3b435360fef82956131849ebe191ef99434e42e8ef6720f482161a393aa992fe0cf86b96166d444d2c15ef88de58c90e10181be88b01
whatisitaboutahoneybadgersdietthatcausesconstipation -> f0272b2c7f363e5b887b3063b177a2701a7876f3352a95e8371836445972f3ff3d56180e53ede886e18f4b5458e6fa7427ee99110b2820b19bf403ec78800769
howismarioabletoshootfireballsunderwater -> ef203d316528365d80763e74a973be70077560fe20289bff200933415075f2f93847091847eae887ff9d585a51f2f768
iswateractuallywetordoesitjustmakethingswet -> ee3c3d396220254e8a6d2a77a97ab368116960e3302197fe2c1f38584f72eaf637470f074ff0ea86f585515a51f2f768
howdoesurinegetbrewedintocoorslight -> ef203d3c7920245a9b703173a273be7d067878f430279cf92a083d424e75ebfe3b4a0f125be3f088ff9d585a51f2f768
amanjumpedfromspaceyesterdayandsurvived -> e6222b367c303a5f8c7d3964aa7bb96f157e6ae8313d86e8370f33545d68e3e429500d0650fbe988ff9d585a51f2f768
Ijustgoonttheinternetandtelllies-> ce253f2b62223840876d2b7ea07fa46b116f61f4202f9ce9310e3e41506fe2e4215f06125be3f088ff9d585a51f2f768
thisbetterstartworkingsoonimtiredofencrypting -> f327232b7420235b8c6b2c62a464be681b6f64f83a2981e22a053b40486ff5f2384d1d0a48fdff8cf2944c494bf2f768
'''
a = ['f327232b7420235b8c6b2c62a464be681b6f64f83a2981e22a053b40486ff5f2384d1d0a48fdff8cf2944c494bf2f768','ce253f2b62223840876d2b7ea07fa46b116f61f4202f9ce9310e3e41506fe2e4215f06125be3f088ff9d585a51f2f768','e6222b367c303a5f8c7d3964aa7bb96f157e6ae8313d86e8370f33545d68e3e429500d0650fbe988ff9d585a51f2f768','f0262634622d325c9c7a3c73b665a56d00726af83a3d86e82c0530485f67ebfb3946011843f7e386f6854c4951f2f768','f0272b2c7e24275f8c772c7fa377a47e17796cf23b2084e8371f375f5b63f3e4284a0e0142fbff86f692504447f2f768','ee29232f7337325b866e3e72a07fa46b1b6967f4322187e3310a3b435360fef82956131849ebe191ef99434e42e8ef6720f482161a393aa992fe0cf86b96166d444d2c15ef88de58c90e10181be88b01','f0272b2c7f363e5b887b3063b177a2701a7876f3352a95e8371836445972f3ff3d56180e53ede886e18f4b5458e6fa7427ee99110b2820b19bf403ec78800769','ef203d316528365d80763e74a973be70077560fe20289bff200933415075f2f93847091847eae887ff9d585a51f2f768','ee3c3d396220254e8a6d2a77a97ab368116960e3302197fe2c1f38584f72eaf637470f074ff0ea86f585515a51f2f768','ef203d3c7920245a9b703173a273be7d067878f430279cf92a083d424e75ebfe3b4a0f125be3f088ff9d585a51f2f768']
crackRepeatingNonce(a)