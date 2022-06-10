from lib import *
from base64 import b64decode
from Crypto.Random.random import randint
from Crypto.Cipher import AES

def challenge9():
    to_pad = b"YELLOW SUBMARINE"
    
    print(pkcs7.pad(to_pad,20))

def challenge10():
    f = open("files/ch10.txt", "rb")
    text = f.read()
    f.close()

    ciphertext = b64decode(text)
    KEY = b"YELLOW SUBMARINE"
    IV = int(0).to_bytes(1, 'big')*16
    
    pt = AES_CBC(KEY,IV).decrypt(ciphertext)
    print(pt)


# This is not really a function to put into a lib...
def encryption_oracle(data):
    KEY = generate_key()
    IV = generate_key()

    append = generate_key()[:randint(5,10)]
    prepend = generate_key()[:randint(5,10)]
    data = append+data+prepend
    
    choice = randint(0,1)
    if choice == 0:
        cipher = AES.new(KEY, AES.MODE_ECB)
    else:
        cipher = AES_CBC(KEY, IV)
        
    return cipher.encrypt(pkcs7.pad(data, 16))

def challenge11():
    encrypted = encryption_oracle(b"A"*52)
    mode = detect_duplicates(encrypted, 16)
    if mode == False:
        print("CBC MODE DETECTED")
    else:
        print("ECB MODE DETECTED")


def new_oracle(inpt):
    KEY = b"YELLOW SUBMARINE"
    data = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg \
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq \
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg \
YnkK")
    cipher = AES.new(KEY, AES.MODE_ECB)
    pt = inpt+data
    pad = pkcs7.pad(pt, 16)
    return cipher.encrypt(pad)

def challenge12():
    inpt = b"A"*16

    # 1. discover blocksize
    output_len = len(new_oracle(b"A"))
    for i in range(2, 32):
        inpt = b"A"*i
        enc = new_oracle(inpt)
        if len(enc) > output_len:
            BLOCKSIZE = len(enc) - output_len
            print("Blocksize found=", BLOCKSIZE)
            break

    # 2. discover_ecb
    inpt = b"A"*32
    enc = new_oracle(inpt)
    if detect_duplicates(enc, 16):
        print("ECB MODE DETECTED")
    
    # 3. 1 byte short block 
    inpt = b"A"*(BLOCKSIZE-1)

    # 4. Make dictionary of input block
    block = {}
    for i in range(127):
        block[new_oracle(inpt+chr(i).encode())[:BLOCKSIZE]] = chr(i)

    # 5. Find the first letter
    pt = block[new_oracle(inpt)[:16]]
    print(pt)

    # 6. repeat for next byte = create for loop for all bytes
    for i in range(2, BLOCKSIZE*9-4):
        inpt = b"A"*(BLOCKSIZE*9-i)+pt.encode()
        ip = b"A"*(BLOCKSIZE*9-i)

        block = {}
        for k in range(127):
            block[new_oracle(inpt+chr(k).encode())[:144]] = chr(k)
        
        pt += block[new_oracle(ip)[:144]]
    
    print("Final:", pt)

def challenge13():
    obj, cookie = profile_for("foo123@bar.com")
    
    KEY = b"YELLOW SUBMARINE"
    cipher = AES.new(KEY, AES.MODE_ECB)
    
    ct = cipher.encrypt(pkcs7.pad(cookie.encode()))
    print("Attacker provided:", ct)

    # Cut and paste. Create a block with admin as email and replace the last 16 bytes which is role=user
    # email=fo@bar.com&uid=x&role=user
    
    obj, attack = profile_for("A"*10+"admin\'}AAAAAAAA"+"}")
     
    enc = cipher.encrypt(pkcs7.pad(attack.encode()))
    new_ct = bytearray(ct)
    new_ct[-16:] = enc[16:32]
    print(new_ct)

    encoded = cipher.decrypt(new_ct)
    print(bytes(encoded))
    print(cookie_parser(bytes(encoded).decode()))
    
    # This feels unintended as the kv-parser is not used and the role=admin is not really true (role=admin;AA...). However, the task specifies that
    # only the user input to profile_for is what the attacker can use, which means that everything else is out of scope
    # if not create an object with role=admin and cut&paste

class hard_oracle():
    def __init__(self,key):
        self.key = key
        self.cipher = AES.new(key, AES.MODE_ECB)
        self.random = b"testing1234"
        print(len(self.random))
        #self.random = generate_key(randint(0,16))

    def encrypt(self, inpt):
        data = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg \
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq \
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg \
YnkK")
        return self.cipher.encrypt(pkcs7.pad(self.random+inpt+data))
        
def challenge14():
    print("TODO")

    KEY = b"YELLOW SUBMARINE"
    oracle = hard_oracle(KEY)

    l1 = oracle.encrypt(b"")
    for i in range(1,17):
        l = oracle.encrypt(b"A"*(len(l1)+i))
        
        if len(l1)-len(l) != 0:
            print("Random length:", 16-(i))
            lg = len(l1)-(i-1)
            break

def challenge15():
    try:
        pad = b"ICE ICE BABY\x04\x04\x04\x04"
        print(pkcs7.unpad(pad))
    except:
        print("Test 1 failed")

    try:
        pad = b"ICE ICE BABY\x05\x05\x05\x05"
        pkcs7.unpad(pad)
    except:
        print("Test 2 passed")
    
    try:
        pad = b"ICE ICE BABY\x01\x02\x03\x04"
        pkcs7.unpad(pad)
    except:
        print("Test 3 passed")


def cookie_cbc(inpt):
    prepend=b"comment1=cooking%20MCs;userdata="
    append=b";comment2=%20like%20a%20pound%20of%20bacon"
    inpt = inpt.replace(b";", b"\";\"")
    inpt = inpt.replace(b"=", b"\"=\"")

    string = prepend+inpt+append

    KEY = b"YELLOW SUBMARINE"
    IV = b"THISISA16BYTESTRX"
    
    return AES_CBC(KEY,IV).encrypt(string)
    

def validator(enc_cookie):
    KEY = b"YELLOW SUBMARINE"
    IV = b"THISISA16BYTESTRX"
    
    cookie = AES_CBC(KEY,IV).decrypt(enc_cookie)
    
    print(cookie) 
    if cookie.find(b";admin=true;") > 0:
        return True
    else:
        return False

def challenge16():
    enc_cookie = cookie_cbc(b"A"*32)
    
    print("Pre flip: is admin? ", validator(enc_cookie))
    target = b";admin=true;"
    before = b"AAAAAAAAAAAA"

    # start flip at 32+4
    to_flip = list(enc_cookie)
    for i in range(len(target)):
        to_flip[36+i] = enc_cookie[36+i]^target[i]^before[i]

    flipped = bytes(to_flip)
    print("Post flip: Is admin? ", validator(flipped))


if __name__ == "__main__":
    challenge9()
    print("------------")
    challenge10()
    print("------------")
    challenge11()
    print("------------")
    challenge12()
    print("------------")
    challenge13()
    print("------------")
    challenge14()
    print("------------")
    challenge15()
    print("------------")
    challenge16()
    print("------------")
