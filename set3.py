from lib import *
from Crypto.Random.random import randint
from Crypto.Cipher import AES

class CBC_PADDING_ORACLE():

    def __init__(self):
        self.KEY = generate_key()
        self.IV = generate_key()
        
    def encrypt(self, string):
        aes = AES.new(self.KEY, AES.MODE_CBC, self.IV)
        padded = pkcs7.pad(string)
        return aes.encrypt(padded)
    
    def valid_padding(self, ciphertext):
        aes = AES.new(self.KEY, AES.MODE_CBC, self.IV)
        plaintext = aes.decrypt(ciphertext)
        
        try:
            pkcs7.unpad(plaintext)
        except:
            return False

        return True

def challenge17():
    f = open("files/ch17.txt", "rb")
    strings = f.read().splitlines()
    f.close()

    plaintext = strings[randint(0,len(strings)-1)]

    oracle = CBC_PADDING_ORACLE()
    
    ciphertext = oracle.encrypt(plaintext)
    
    print(oracle.valid_padding(ciphertext))



if __name__ == "__main__":
    challenge17()
    print("------------")
