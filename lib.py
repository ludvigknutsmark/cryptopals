from base64 import b64encode
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

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

def detect_duplicates(data, BLOCKSIZE):
    blks = [data[i:i+BLOCKSIZE] for i in range(0,len(data), BLOCKSIZE)]
    # Ugly but readable code for finding duplicate values in list...
    dupes = []
    dupes_found = False
    for blk in blks:
        if blk not in dupes:
            dupes.append(blk)
        else:
            dupes_found = True

    return dupes_found
    
def cookie_parser(cookie):
    kv = cookie.split("&")
    obj = {}
    for pair in kv:
        key,value=pair.split("=")
        try:
            obj[key] = int(value)
        except:
            obj[key] = value
    
    return obj

def profile_for(email):
    email.replace("&","")
    email.replace("=","")
    uid = randint(0,10)
    role= "user"
    cookie = "email="+email+"&uid="+str(uid)+"&role="+role
    return cookie_parser(cookie), cookie #unsure what to provide atm

#------------------------------------------
#           AES STUFF
#------------------------------------------
def generate_key(blksize=16):
    return get_random_bytes(blksize)    

class pkcs7():
    def pad(data, blksize=16):
        padsize = (blksize-len(data)) % blksize
        return data+padsize.to_bytes(1, 'big')*padsize

    def unpad(data,blksize):
        print("unpad")

from Crypto.Cipher import AES
class AES_CBC():
    def __init__(self, key, IV, blksize=16):
        self.key = key
        self.IV = IV
        self.blksize = blksize
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, data):
        padded = pkcs7.pad(data, self.blksize)
        encrypted = bytes()
        encrypted += self.cipher.encrypt(xor(self.IV, padded[:self.blksize]))

        for i in range(self.blksize, len(padded), self.blksize):
            cur_blk = padded[i:i+self.blksize]
            prev_blk = encrypted[-self.blksize:]
            encrypted += (self.cipher.encrypt(xor(cur_blk, prev_blk)))

        return encrypted

    def decrypt(self, data):
        prev_blk = self.IV
        
        plaintext = bytes()
        for i in range(0, len(data), self.blksize):
            cur_blk = data[i:i+self.blksize]
            plaintext += xor(self.cipher.decrypt(cur_blk), prev_blk)
            prev_blk = cur_blk

        return plaintext

if __name__ == "__main__":
    assert hex2b64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".encode()

    assert xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "the kid don't play".encode()

    assert hamming(b"this is a test", b"wokka wokka!!!") == 37
