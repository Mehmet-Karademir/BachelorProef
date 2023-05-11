import time
import csv

import pqcrypto.sign.dilithium2 as dilithium2
import pqcrypto.sign.dilithium3 as dilithium3
import pqcrypto.sign.dilithium4 as dilithium4
import pqcrypto.sign.falcon_1024 as falcon_1024
import pqcrypto.sign.falcon_512 as falcon_512
import pqcrypto.sign.sphincs_sha256_128f_robust as sphincs_sha256_128f_robust
import pqcrypto.sign.sphincs_sha256_128f_simple as sphincs_sha256_128f_simple 
import pqcrypto.sign.sphincs_sha256_128s_robust as sphincs_sha256_128s_robust
import pqcrypto.sign.sphincs_sha256_128s_simple as sphincs_sha256_128s_simple
import pqcrypto.sign.sphincs_sha256_192f_robust as sphincs_sha256_192f_robust
import pqcrypto.sign.sphincs_sha256_192f_simple as sphincs_sha256_192f_simple
import pqcrypto.sign.sphincs_sha256_192s_robust as sphincs_sha256_192s_robust
import pqcrypto.sign.sphincs_sha256_192s_simple as sphincs_sha256_192s_simple
import pqcrypto.sign.sphincs_sha256_256f_robust as sphincs_sha256_256f_robust
import pqcrypto.sign.sphincs_sha256_256f_simple as sphincs_sha256_256f_simple
import pqcrypto.sign.sphincs_sha256_256s_robust as sphincs_sha256_256s_robust
import pqcrypto.sign.sphincs_sha256_256s_simple as sphincs_sha256_256s_simple

algorithms = [dilithium2, dilithium3, dilithium4, falcon_1024, falcon_512, sphincs_sha256_128f_robust, sphincs_sha256_128f_simple, sphincs_sha256_128s_robust,
              sphincs_sha256_128s_simple, sphincs_sha256_192f_robust, sphincs_sha256_192f_simple, sphincs_sha256_192s_robust, sphincs_sha256_192s_simple,
              sphincs_sha256_256f_robust, sphincs_sha256_256f_simple, sphincs_sha256_256s_robust, sphincs_sha256_256s_simple]

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
    for algorithm in algorithms:

        t_end = time.time() + runTime
        amount = 0

        while time.time() < t_end:
            pk, sk = algorithm.generate_keypair()
            amount = amount+1

        if time.time() > t_end:
            amount = amount-1

        keygen = runTime/amount
        keygenPerSec = 1/keygen

        name = algorithm.__name__.split('.')[2]

        print("-----------------------------------")
        print(name)
        print("Amount of keys generatred: " + str(amount))
        print("Keygen Time/s: " +  str(keygenPerSec))
        print("Keygen: " + str(keygen))
        print("-----------------------------------")

        #save data in csv file
        writer.writerow((name,amount,keygen,keygenPerSec))

def SignTesting(runTime, writer):
    for algorithm in algorithms:
        pk, sk = algorithm.generate_keypair()

        t_end = time.time()+runTime
        amount = 0

        while time.time() < t_end:
            signature = algorithm.sign(sk, b"This is a message that will be signed")
            amount = amount + 1

        sign = runTime/amount
        signPerSec = 1/sign

        name = algorithm.__name__.split('.')[2]

        print("-----------------------------------")
        print(name)
        print("Amount of signatures: " + str(amount))
        print("Signatures/s: " +  str(signPerSec))
        print("Sign time: " + str(sign))
        print("-----------------------------------")

        #save data in csv file
        writer.writerow((name,amount,sign,signPerSec))

def VerifyTesting(runTime, writer):
    for algorithm in algorithms:
        pk, sk = algorithm.generate_keypair()

        signature = algorithm.sign(sk, b"This is a message that will be signed and verified.")

        t_end = time.time()+runTime
        amount = 0

        while time.time() < t_end:
            assert algorithm.verify(pk,b"This is a message that will be signed and verified.",signature)
            amount = amount + 1

        sign = runTime/amount
        signPerSec = 1/sign

        name = algorithm.__name__.split('.')[2]

        print("-----------------------------------")
        print(name)
        print("Amount of signatures: " + str(amount))
        print("Signatures/s: " +  str(signPerSec))
        print("Sign time: " + str(sign))
        print("-----------------------------------")

        #save data in csv file
        writer.writerow((name,amount,sign,signPerSec))

main()
