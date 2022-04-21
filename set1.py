from lib import *
from base64 import b64decode
from Crypto.Cipher import AES

def challenge1():
    print(hex2b64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".encode())

def challenge2():
    print(xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))

def challenge3():
    ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
   
    possible_key = find_xor_key(ciphertext)
    print("possible key: ", possible_key)

    plaintext = xor(ciphertext, hex(int(possible_key))[2:]*len(ciphertext))
    print("plaintext:", plaintext)

def challenge4():
    f = open("files/ch4.txt", "rb")
    ciphertexts = f.read().splitlines()
    f.close()
    plaintext_candidate = {}
    
    pos = 0
    for ciphertext in ciphertexts:
        pos += 1
        ciphertext = ciphertext.decode()
        possible_key = find_xor_key(ciphertext)
        plaintext = xor(ciphertext, hex(int(possible_key))[2:]*len(ciphertext))
                     
        plaintext_candidate[str(pos)] = (character_freq(plaintext), plaintext)
    
    candidate = sorted(plaintext_candidate.items(), key=lambda x: x[1], reverse=True)[0][1]
    print("Candidate:", candidate)

def challenge5():
    p = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    k = b"ICE"
    key = create_repeating_key(k, len(p))
    assert xor(p, key).hex() == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

def challenge6():
    f = open("files/ch6.txt", "rb")
    text = f.read()
    f.close()

    ciphertext = b64decode(text)

    keysizes = {}
    for KEYSIZE in range(2,40):
        b1 = ciphertext[:KEYSIZE]
        b2 = ciphertext[KEYSIZE:KEYSIZE*2]
        b3 = ciphertext[KEYSIZE*2:KEYSIZE*3]
        
        keysizes[str(KEYSIZE)] = (hamming(b1,b2)+hamming(b1,b3)+hamming(b2,b3))  // 3*KEYSIZE

    keysize_candidate = sorted(keysizes.items(), key=lambda x: x[1], reverse=True)[:10]
    
    for keysize in keysize_candidate:
        KEYSIZE = int(keysize[0])
        blks = [ciphertext[i:i+KEYSIZE] for i in range(0,len(ciphertext), KEYSIZE)]

        transposed = []
        for k in range(KEYSIZE):
            b = bytearray()
            for blk in blks:
                if k < len(blk):
                    b.append(blk[k])
            transposed.append(bytes(b))
        
        possible_key = ""
        for t_blk in transposed:
            possible_key+=chr(find_xor_key(t_blk.hex()))
            
        print("possible key: ", possible_key.encode())
        print("possible plaintext:", xor(ciphertext, create_repeating_key(possible_key.encode(), len(ciphertext)))[:20])

def challenge7():
    f = open("files/ch7.txt", "rb")
    text = f.read()
    f.close()

    ciphertext = b64decode(text)
    KEY = b"YELLOW SUBMARINE"

    cipher = AES.new(KEY, AES.MODE_ECB)
    print(cipher.decrypt(ciphertext))


def challenge8():
    f = open("files/ch8.txt", "rb")
    text = f.read().splitlines()
    f.close()
    
    # Split each text into the corresponding 16 byte blocks (32 byte hex)
    BLOCKSIZE = 16*2
    duplicate_count={}
    for ciphertext in text:
        blks = [ciphertext[i:i+BLOCKSIZE] for i in range(0,len(ciphertext), BLOCKSIZE)]
        
        # Ugly but readable code for finding duplicate values in list...
        dupes = []
        dupe_count = 1
        for blk in blks:
            if blk not in dupes:
                dupes.append(blk)
            else:
                dupe_count += 1
        duplicate_count[str(ciphertext)] = dupe_count

    encrypted_candidate = sorted(duplicate_count.items(), key=lambda x: x[1], reverse=True)[0]
    print("Encrypted candidate: ", encrypted_candidate[0], "\nDuplicates=", encrypted_candidate[1])


if __name__ == "__main__":
    challenge1()
    print("-----------")
    challenge2()
    print("-----------")
    challenge3()
    print("-----------")
    challenge4()
    print("-----------")
    challenge5()
    print("-----------")
    challenge6()
    print("-----------")
    challenge7()
    print("-----------")
    challenge8()
    print("-----------")
