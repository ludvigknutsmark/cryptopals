from base64 import b64encode

def hex2b64(heks):
    b = bytes.fromhex(heks)
    return b64encode(b)


def xor(b1, b2):
    if type(b1) is not bytes:
        b1 = bytes.fromhex(b1)
    if type(b2) is not bytes:
        b2 = bytes.fromhex(b2)

    return bytes(a^b for(a,b) in zip(b1,b2))

def character_freq(string):
    freq = {}
    freq[' '] = 700000000
    freq['e'] = 390395169
    freq['t'] = 282039486
    freq['a'] = 248362256
    freq['o'] = 235661502
    freq['i'] = 214822972
    freq['n'] = 214319386
    freq['s'] = 196844692
    freq['h'] = 193607737
    freq['r'] = 184990759
    freq['d'] = 134044565
    freq['l'] = 125951672
    freq['u'] = 88219598
    freq['c'] = 79962026
    freq['m'] = 79502870
    freq['f'] = 72967175
    freq['w'] = 69069021
    freq['g'] = 61549736
    freq['y'] = 59010696
    freq['p'] = 55746578
    freq['b'] = 47673928
    freq['v'] = 30476191
    freq['k'] = 22969448
    freq['x'] = 5574077
    freq['j'] = 4507165
    freq['q'] = 3649838
    freq['z'] = 2456495
    
    total = 0
    for s in string.lower():
        try:
            total += freq[chr(s)]
        except:
            pass

    return total

def create_repeating_key(key, length):
    divided = length // len(key)
    wrapper = length % len(key)
    return key*divided+key[:wrapper]

def hamming(b1,b2):
    # create bitstrings
    h1 = bin(int(b1.hex(), 16))[2:]
    h2 = bin(int(b2.hex(), 16))[2:]
    hamming = 0
    for (a,b) in zip(h1,h2):
        if a!=b:
            hamming+=1
    return hamming

def find_xor_key(ciphertext):
    candidates = {}
    for k in range(0,127):
        key = hex(k)[2:]*len(ciphertext)
   
        candidates[str(k)] = character_freq(xor(ciphertext,key))

    possible_key = sorted(candidates.items(), key=lambda x: x[1], reverse=True)[0][0]
    return int(possible_key)

if __name__ == "__main__":
    assert hex2b64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".encode()

    assert xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "the kid don't play".encode()

    assert hamming(b"this is a test", b"wokka wokka!!!") == 37
