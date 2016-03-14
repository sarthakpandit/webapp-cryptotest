This toolset includes a Django web app that implements multiple modes of encryption. At the time of writing this, it can simulate AES in ECB, CBC and CTR modes.

Also included are a set of tools that attack common mistakes made when implementing these ciphers in various modes.

Currently Implemented:

Chosen boundary attack for CBC (fixed IV) and ECB mode.

XOR Frequency Analysis - Attacks CTR mode block or stream ciphers that have a static NONCE or looping CTR.