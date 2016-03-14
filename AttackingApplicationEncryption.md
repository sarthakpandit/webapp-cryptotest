# Attacking Application Encryption #
REFS:
http://www.slideshare.net/ceng/cryptography-for-penetration-testers-pdf-version-presentation

Bruce Schnier - Cryptography Engineering

Tom Ptacek - http://vimeo.com/41116595

## Identify the cipher and look for attacks on the mode of encryption: ##

## Q: Is it a block Cipher or Stream cipher? ##
A: Is the output always a multiple of common block sizes (usually 128bits = 16 bytes)?

Does pushing the input length over the block size cause another block to be added to the output?

If neither are these are true, it's probably a stream cipher or block cipher being used in CTR or some other stream mode. Try modifying a single byte of input, if you see a single byte change in the output it is a broken implementation of a stream cipher, more details to follow.

## Q: Is it ECB Mode (Insecure, You Win)? ##
A: Give a long, repeated input eg: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

This should yield at LEAST 3 repeated blocks in the ciphertext if it is AES ECB

Another test if limited input space availble - do small PT changes cause single block CT changes?

If it is ECB, we can attack it in multiple ways

### Attack - Block Shuffling ###
1) ECB blocks can be shuffled and substituted to modify/tamper with the ciphertext

### Attack - Chosen Boundary Attack - Also works on CBC with static IV ###
http://erlend.oftedal.no/blog/beast/

1) Find out about how many bytes precede our input in the CT - look for where the repeated blocks start

2) Manipulate input so that the LAST block of our repeated input lines up with the block boundary. Do this by starting with large input and removing characters until you LOSE a repeated block. Then REMOVE the last character (byte) from the input so that the first byte of ciphertext is picked up within our last block eg:

AAAAAAAAAAAAAAAA (we have a full block of our repeated input)

AAAAAAAAAAAAAAA? (we remove one character and ‘pick up’ the last character or unknown CT)

3) Perform a dictionary attack to find ? using a previous repeated block. We know we have found x when the ciphertext in the 2 blocks matches eg:

Suppose the last block that contains our input (AAAAAAAAAAAAAAA? where ? is unknown) encrypts as:

AAAAAAAAAAAAAAA? ==> JDJDJEIDLELEMSE32

Then we can use one of the blocks where we control all the characters to brute force ?:

AAAAAAAAAAAAAAAa ==> ZHEKJDKDLENAKEJJ3

AAAAAAAAAAAAAAAb ==> DKMDJOWEKLJDSKNN1

AAAAAAAAAAAAAAAc ==> JDJDJEIDLELEMSE32 **MATCH**

4) To find the next character, remove another character from the last block and modify your block where you control all the characters so that its second from last character is the one found in step 3. Brute force the last character.

5) Repeat.


## Q: Is it CTR Mode? ##
A: Does the ciphertext grow byte-at-a-time as input is added? If so, probably AES w/ CTR, could be RC4 as well, attacks below work for both.

Does a single byte PT change cause a single byte CT change? Indicates broken implementation of a stream cipher (reusing the same NONCE).

Are there repeated strings in the ciphertext? Indicates CTR wrapping and can be attacked.

Must understand how CTR works - Wikipedia/Schneirs book

Vulnerable if we can induce the same keystream to be used for multiple blocks OR multiple messages.

The way the keystream works is there is one unique NONCE per message, a message can be of any length. The counter function C(x) is usually just a simple counter, eg: C(0) = 0, C(1) =1 ... However some implementations will screw this up and have a wrapping or repeating counter. To encrypt the nth block of the message, we AES encrypt the NONCE+C(n) to get 16bytes of ciphertext, then XOR this with block n of the plaintext to get the encrypted block. Decryption is done by XORing the plaintext with the relevant part of the keystream (E(NONCE+C(n))) that was used to encrypt it.

If we can induce the condition where some part of the keystream is repeated (used to encrypt two different blocks of plaintext or 2 different messages) we can possibly recover the content of those plaintext blocks even if they are both unknown. If one is known and one is not, we can DEFINITELY recover it (see the next ‘simple’ attack)

Conditions - Must find 2+ blocks that satisfy:

Same AES key (almost always true)

Same NONCE (Should be unique per message, sometimes can be influenced (parameter), often ZEROED or reused by insecure implementations)

Same Counter (Usually the ith block in all messages will have the same counter value, sometimes a counter will wrap within the same message (look for repeated CT sections, if 3+ bytes of CT repeat, good chance the counter wrapped and we can attack it), sometimes it is timestamp based, sometimes it will count up from a random value...)

Some of these conditions may be able to be induced (i.e. Counter wrapping by providing long input or influencing the NONCE somehow). To know if you’ve gotten it right, you should see multiple blocks of the same plaintext coming out as the same ciphertext. If this is the case, you can break the encryption.

If all you have is a long string of ciphertext (or a bunch of unknown messages), look for repeated strings of bytes. It is VERY unlikely that long strings of bytes will repeat at random, chances are the counter wrapped or nonce was reused. You can use this information to attack the ciphertext as described below.

### Attack - Simple Keystream Attack with SOME known Plain Text and Reused NONCE ###

1) Find the location of some known PT in the CT by trial/error. Supply a long string of input, get the CT. Change the first/last character of your input, look for which bytes in the CT change. If only 2 bytes change and they correspond to the length of your input, this attack will work. This is because they are reusing the nonce between messages.

2) XOR the PT you provided and the CT it encrypted to, this will give you the keystream used to encrypt it. This means we can get arbitrary amounts of keystream starting from where your input begins in the CT.

3a) Now shorten your input to a single character. XOR the keystream you got in step (2) with the ciphertext, starting at the byte in the CT where your input starts. You should get back the plain text!

3b) XOR the same part (byte offset) of the CT in a different message, one you may not control the input to, with the result from (2), may get back plaintext if they are reusing the NONCE which is likely

4) Try XOR'ing key with the correct bytes in more messages from other parts of the application... Any ASCII you find, if you can PREDICT more PT, you can get more keystream. EG if we find “rsonal Inf”, we can try to guess "Personal Information" as the PT, which can give us 10 more bytes of keystream if correct! Go back to step 2 and get more keystream! In this way we can recover the keystream used to encrypt things that occur BEFORE our input in the ciphertext.

### Attack - Keystream Attack with known Plain Text and Looping CTR ###
Read this: http://en.wikipedia.org/wiki/Kasiski_examination

1) Induce and detect looping in the CTR. Provide a long stream of repeated input, look for where repeated strings start to appear in the CT. This is best done with a script, difficult to 'eye' it. The distance between these repeating strings indicates when the counter wraps.

2)Same principle as the attack above but you are using it WITHIN a single message. You recover keystream by XORing CT with the corresponding known plain text. You know the keystream repeated later in the message because you found out where the CTR wrapped, so XOR that keystream with the CT after the CTR wrap and you will get back the plain text.

### Attack - Repeated keystream attack (NO KNOWN PLAINTEXT) (RC4 or AES CTR) ###
Read this: http://en.wikipedia.org/wiki/Kasiski_examination

If you have NO knowledge on what the original plaintext was but you have a bunch of encrypted strings and you suspect the NONCE or CTR repeat, you can apply the above two attacks still by using character frequency analysis.

1) Remember -> ciphertext XOR ciphertext = plaintext XOR plaintext

2) Use statistics about the text you expect to get back (eg: which one produces the most letter e's since its the most common english letter)

3) You can attack this cipher byte-at-a-time

Take all bytes that are suspected to have been encrypted with the same part of the keystream. For example, if you were able to fix the nonce or suspect it is fixed, take the ith byte of each message.

If the nonce is not fixed but you suspect CTR repetition, look for repeated strings in the CT (use a script, read the article at the top of this attack section). Use the distance between repeated strings to estimate where the CTR wraps. This tells you where the keystream starts to repeat. Knowing this, you can collect bytes encrypted with the same keystream.

If the NONCE is not fixed and there doesn't seem to be any repeated strings in any of the messages you have, try concatenating all of the messages into a single, long string and looking for repetitions in that. This will allow you to detect any NONCE or CTR repetition.

Brute force the corresponding key byte by checking which value for the key byte produces the most common characters according to the characte frequency you expect (e.g. English has the highest frequency letter as ‘e’, so look for the most ‘e’s if you think the PT was English). Again this should be scripted and you can use more complex frequency analysis.

E.G. Suppose you have 5 16 byte blocks of unknown ciphertext encrypted with the same part of the keystream

-Byte 1 of each block will have been encrypted (XOR’d) with byte 1 of the key

-Brute force byte 1 by XORing the CT with all possible values for that byte - look for highest freqeuncy of the letter 'e' across your 5 bytes at this position

-Repeat for remaining bytes, hopefully you get something intelligable

## Q: Is it CBC Mode? ##
A: Blocks don't repeat, small PT changes cause full or large CT changes

-Do you see static text in fixed locations of each CT (usually beginning)? Probably an Initialization Vector

-Do you see repetition across messages but not blocks? The beginning of long strings encrypts to the same ciphertext, but blocks are not repeated? Probably CBC with a static IV. This will be vulnerable to the chosen boundary attack described for ECB.

### Attack: Padding Oracle Attack (e.g. PadBuster/IIS Vuln) ###

http://blog.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html

A CBC implementation is vulnerable to padding oracle attacks under the following conditions:

1) When valid CT is submitted to the application and it decrypts to valid data you get a distinguishable response (eg: 200 OK)

2) When CT is submitted that decrypts to invalid data but has valid padding you get a distinguishable response (eg: 200 OK with a custom error or something)

3) When invalid CT is submitted and the padding is incorrect you get a distinguishable response (eg: 500 Error due to crypto libraries crapping out on the backend)

An example of how this can be satisfied is (1) giving the 200 OK response and fulfilling a request, (2) gives an application level error because the decrypted data is invalid in the application context, (3) gives a server error (exception is thrown when the decryption fails). As long as errors (2) and (3) are different, we can use a padding oracle attack to decrypt the ciphertext that is being submitted to the application.

### Attack: Static or repeated IV ###
Vulnerable to the chosen boundary attack described for ECB.

### Attack: Bitflipping and CBC Block Shuffling ###

http://namnham.blogspot.com/2010/03/codegate-2010-ctf-challenge-8-cbc-mode.html

-Very interesting attack method although there is one confusing part of the article:

Look at this section from the article:

>>> iv, cipher = get\_cookie('1234567890123456')

>>> cipher1 = cipher[:32] + iv + cipher[:16]

>>> username, role = get\_message(iv, cipher1)

'Welcome back, 1234567890123456! Your role is: E\x9bpY?\xfbW6\x84{\x8fn\x1e\x80\x10\x1busername=1234567. You need admin role.'

It is not explained, but what is happening here is really cool. If an application is decrypting some part of the encrypted value and displaying it, and you want to know some OTHER part of the encrypted value, plug the block+previous block in where the stuff is being displayed from. In this case, he wanted to know what the first 16 bytes of ciphertext were so he used IV+cipher[:16]. What happens here is on decryption, the PT is xored with the previous block of CT, so the IV gets jumbled on decryption but the cipher[:16] block is decrypted correctly.


## Hashes: ##

Q: Does the application validate messages based on the hash of the message with a secret key? This is not a valid way to use CURRENT hashing algorithms (MD5, SHA1, SHA256) but some applications do it anyways (Flikr compromise and Stripe CTF). -- New tool and article by skull security on this! http://www.skullsecurity.org/blog/2012/everything-you-need-to-know-about-hash-length-extension-attacks

E.G. Suppose X is a secret and M is the message, h(X | M) is used to validate M comes from a trusted source. We can modify M (lengthen it) to M’ and compute h(X | M’) without knowing X because of how current hash functions work.

h(X | M) is actually an intermediate value when computing h(X | M'), so we seed the hash function with h(X | M) which is known, then we compute the hash for our extension. The trick is to pad the extension message at the beginning so that our entire extension falls into a new block AND doesn't modify anything in the previous block. To do this, we prepend out extension with the padding the hash algorithm uses. This has the form:

0x800000000000....xxxxxxxx

Where xxxxxxxx is the number of bits of unpadded data in the block.