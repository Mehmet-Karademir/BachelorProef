import time
import csv 

from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
parameterBits = [1024, 2048, 3072]


def main():
    #prepare csv file for saving results
    f1 = open("./Results/Keygen.csv","a",newline="")
    KeygenWriter = csv.writer(f1)

    f2 = open("./Results/Sign.csv","a",newline="")
    SignWriter = csv.writer(f2)

    f3 = open("./Results/Verify.csv","a",newline="")
    VerifyWriter = csv.writer(f3)

    #set run time
    runTime = 100
    print("Current run time is: " + str(runTime))

    #start testing
    print("Testing Key generation speed")
    KeyGenTesting(runTime, KeygenWriter)

    print("Testing signature speed")
    SignTesting(runTime,SignWriter)

    print("Testing verification speed")
    VerifyTesting(runTime,VerifyWriter)

    #close files
    f1.close()
    f2.close()
    f3.close()

def KeyGenTesting(runTime, writer):
    for bits in parameterBits:

        t_end = time.time() + runTime
        amount = 0

        while time.time() < t_end:
            privkey = DSA.generate(bits)
            pubkey = privkey.public_key()
            amount = amount + 1

        if time.time() > t_end:
            amount = amount-1

        keygen = runTime/amount
        keygenPerSec = 1/keygen

        print("-----------------------------------")
        print(bits)
        print("Amount of keys generatred: " + str(amount))
        print("Keygen Time/s: " +  str(keygenPerSec))
        print("Keygen: " + str(keygen))
        print("-----------------------------------")

        #save data in csv file
        name = "DSA-"+str(bits)
        writer.writerow((name,amount,keygen,keygenPerSec))

def SignTesting(runTime, writer):
    for bits in parameterBits:
        privkey = DSA.generate(bits)

        hash_obj = SHA256.new(b"This is a message that will be signed")
        signer = DSS.new(privkey, 'fips-186-3')

        t_end = time.time()+runTime
        amount = 0

        while time.time() < t_end:
            signature = signer.sign(hash_obj)
            amount = amount + 1

        sign = runTime/amount
        signPerSec = 1/sign

        print("-----------------------------------")
        print(bits)
        print("Amount of signatures: " + str(amount))
        print("Signatures/s: " +  str(signPerSec))
        print("Sign time: " + str(sign))
        print("-----------------------------------")

        #save data in csv file
        name = "DSA-"+str(bits)
        writer.writerow((name,amount,sign,signPerSec))

def VerifyTesting(runTime, writer):
    for bits in parameterBits:
        privkey = DSA.generate(bits)
        pubkey = privkey.public_key()

        hash_obj = SHA256.new(b"This is a message that will be signed and verified.")
        signer = DSS.new(privkey, 'fips-186-3')
        signature = signer.sign(hash_obj)

        verifier = DSS.new(pubkey, 'fips-186-3')

        t_end = time.time()+runTime
        amount = 0

        while time.time() < t_end:
            verifier.verify(hash_obj, signature)
            amount = amount + 1

        verify = runTime/amount
        verifyPerSec = 1/verify

        print("-----------------------------------")
        print(bits)
        print("Amount of signatures: " + str(amount))
        print("verify/s: " +  str(verifyPerSec))
        print("verify time: " + str(verify))
        print("-----------------------------------")

        #save data in csv file
        name = "DSA-"+str(bits)
        writer.writerow((name,amount,verify,verifyPerSec))

main()