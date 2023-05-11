import time
import csv

from ecdsa import SigningKey, NIST192p, NIST224p, NIST256p, NIST384p, NIST521p
curves = [NIST192p, NIST224p, NIST256p, NIST384p, NIST521p]

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
    f1.close
    f2.close
    f3.close

def KeyGenTesting(runTime, writer):
    for curveSettings in curves:
        t_end = time.time() + runTime
        amount = 0

        while time.time() < t_end:
            sk = SigningKey.generate(curve= curveSettings)
            vk = sk.verifying_key
            amount = amount + 1

        if time.time() > t_end:
            amount = amount-1


        keygen = runTime/amount
        keygenPerSec = 1/keygen

        print("-----------------------------------")
        print(curveSettings.name)
        print("Amount of keys generatred: " + str(amount))
        print("Keygen Time/s: " +  str(keygenPerSec))
        print("Keygen: " + str(keygen))
        print("-----------------------------------")

        #save data in csv file
        writer.writerow((curveSettings.name,amount,keygen,keygenPerSec))

def SignTesting(runTime, writer):
    for curveSettings in curves:
        sk = SigningKey.generate(curve=curveSettings)

        t_end = time.time()+runTime
        amount = 0

        while time.time() < t_end:
            signature = sk.sign(b"This is a message that will be signed")
            amount = amount + 1

        sign = runTime/amount
        signPerSec = 1/sign

        print("-----------------------------------")
        print(curveSettings.name)
        print("Amount of signatures: " + str(amount))
        print("Signatures/s: " +  str(signPerSec))
        print("Sign time: " + str(sign))
        print("-----------------------------------")

        #save data in csv file
        writer.writerow((curveSettings.name,amount,sign,signPerSec))

def VerifyTesting(runTime, writer):
    for curveSettings in curves:
        sk = SigningKey.generate(curve=curveSettings)
        vk = sk.verifying_key
        signature = sk.sign(b"This is a message that will be signed and verified.")
        t_end = time.time()+runTime
        amount = 0

        while time.time() < t_end:
            vk.verify(signature, b"This is a message that will be signed and verified.")
            amount = amount + 1

        verify = runTime/amount
        verifyPerSec = 1/verify

        print("-----------------------------------")
        print(curveSettings.name)
        print("Amount of signatures: " + str(amount))
        print("verify/s: " +  str(verifyPerSec))
        print("verify time: " + str(verify))
        print("-----------------------------------")

        #save data in csv file
        writer.writerow((curveSettings.name,amount,verify,verifyPerSec))

main()