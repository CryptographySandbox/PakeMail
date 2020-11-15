from io import StringIO
from email.mime.base import MIMEBase
from email.message import Message
import base64
import mimetypes
import os
from spake2 import SPAKE2_A
from spake2 import SPAKE2_B
from spake2.parameters.i1024 import Params1024
from spake2.parameters.i2048 import Params2048
from spake2.parameters.i3072 import Params3072
from pakemail import PakeMail, PakeMailService
from pakemod import PakeClient,Roles,Parameters
import pakemod
import nacl.secret, nacl.utils
import sys
from threading import Thread
import getpass, time, timeit
import gnupg

def generateKeyPairForEmail():
    email = input("Please enter an email address:")
    phrase = getpass.getpass("Please enter a passphrase:")
    gpg = pakemod.getGpgHandler()
    key_data = gpg.gen_key_input(key_type="RSA", key_length=2048, name_email=email, passphrase=phrase)
    gpg.gen_key(key_data)

def runCryptoExperiment(pake_key, message):
    print("-------------------------------------------------------------------")
    print("Encrypting and decrypting a message using the PAKE-generated key...")
    secret_box = nacl.secret.SecretBox(pake_key)

    print("The following message will be encrypted:")
    print(message.decode('utf-8'))
    encrypted = secret_box.encrypt(message)
    print("The obtained ciphertext is\n", encrypted)

    print("The decrypted plaintext is:")
    plaintext = secret_box.decrypt(encrypted)
    print(plaintext.decode('utf-8'))

def run_local_pake_test():
    executionTime = float(0)
    start = time.process_time()

    pakeClientA = PakeClient("A", "pass", "test+senderA@gmail.com", parameters=Params1024)
    pakeClientB = PakeClient("B", "pass", "test+receiverB@gmail.com", parameters=Params1024)

    pakeClientA.registerRemotePakeClient(pakeClientB)
    pakeClientB.registerRemotePakeClient(pakeClientA)

    pakeClientA.setup(localTest=True)
    pakeClientB.setup(localTest=True)


    pakeMsgA1 = pakeClientA.pakeMessage
    pakeMsgB2 = pakeClientB.pakeMessage

    pakeClientA.computeKey(pakeMsgB2)
    keyA = pakeClientA.key
    
    pakeClientB.computeKey(pakeMsgA1)
    keyB = pakeClientB.key

    print(base64.b64encode(keyA))
    print(base64.b64encode(keyB))
    print("Intermediate secret keys match: ", keyA == keyB)

    print("Key confirmation starts...")

    kA, aMacKeyA, aMacKeyB = pakeClientA.runKeyDerivation()
    pakeClientA.computeTranscript()
    macMessageA = pakeClientA.pkAfpr+pakeClientA.pkBfpr+pakeClientA.transcript
    print("MAC message A:", macMessageA)
    tauA = pakeClientA.computeMAC(aMacKeyA, macMessageA)
    pakeClientA.createMacMsg(tauA, writeToFile=True)
    print("tau_A :\n", tauA)

    expected_tauB = pakeClientA.computeMAC(aMacKeyB, macMessageA)
    print("expected tau_B :\n", expected_tauB)

    kB, bMacKeyA, bMacKeyB = pakeClientB.runKeyDerivation()
    pakeClientB.computeTranscript()
    macMessageB = pakeClientB.pkAfpr+pakeClientB.pkBfpr+pakeClientB.transcript
    print("MAC message B:", macMessageB)
    tauB = pakeClientB.computeMAC(bMacKeyB, macMessageB)
    pakeClientB.createMacMsg(tauB, writeToFile=True)
    print("tau_B :\n", tauB)

    expected_tauA = pakeClientB.computeMAC(bMacKeyA, macMessageB)
    print("expected tau_A :\n", expected_tauA)

    print("----------------------------------------------------")
    print("Tags match on A side: ", tauB == expected_tauB)
    print("Tags match on B side: ", tauA == expected_tauA)
    print("Final secret keys are: \n{0}\n{1}\nand have length {2} and {3}".format(base64.b64encode(kA),base64.b64encode(kB),len(kA), len(kB)))
    print("Final secret keys match: ", kA==kB)

    runCryptoExperiment(kA, b"This plaintext will be encrypted using a PAKE-generated secret key")

    executionTime = (time.process_time() - start)
    print("Local PakeMail execution time: ", executionTime)

def run_pake_session_over_gmail():
    senderEmail = ""
    receiverEmail = ""
    senderPass = ""
    receiverPass = ""

    senderPass = "pass"
    receiverPass = "pass"

    if senderEmail == "":
        senderEmail = input("Please enter a sender/initiator email address:")
    if receiverEmail == "":
        receiverEmail = input("Please enter a receiver/responder email address:")

    if senderPass == "":
        senderPass = getpass.getpass("Please enter the sender PAKE password:")
    if receiverPass == "":
        receiverPass = getpass.getpass("Please enter the receiver PAKE password:")
    

    executionTime = float(0)
    start = time.process_time()

    pakeClientA = PakeClient("A", senderPass, senderEmail)
    pakeClientB = PakeClient("B", receiverPass, receiverEmail)
    
    pakeClientA.registerRemotePakeClient(pakeClientB)
    pakeClientB.registerRemotePakeClient(pakeClientA)

    executionTime += (time.process_time() - start)

    pakeClientA.setup()
    pakeClientB.setup()

    start = time.process_time()

    pakeClientB.pakeMail.setID(pakeClientA.pakeMail.id, messageType="pakeMac")
    pakeClientB.pakeMail.setID(pakeClientA.pakeMail.id, messageType="pakeMessage")

    executionTime += (time.process_time() - start)

    t1 = Thread(target = pakeClientA.runSession)
    t1.start()
    
    t2 = Thread(target = pakeClientB.runSession)
    t2.start()
    
    t1.join()
    t2.join()

    executionTime += pakeClientA.executionTime
    print("PAKE client Thread finished after {0} seconds...exiting".format(executionTime))

def run_pake_session_as_initiator():
    print("\t***  Running a PAKE client as initiator ***")

    senderEmail = input("Please enter a sender/initiator email address (i.e. yours):")
    receiverEmail = input("Please enter a receiver/responder email address:")
    senderPass = getpass.getpass("Please enter the sender/initiator PAKE password:")

    pakeClientA = PakeClient("A", senderPass, senderEmail)
    pakeClientB = PakeClient("B", senderPass, receiverEmail)

    pakeClientA.registerRemotePakeClient(pakeClientB)
    pakeClientB.registerRemotePakeClient(pakeClientA)

    pakeClientA.setup()

    t1 = Thread(target = pakeClientA.runSession)
    t1.start()
    
    t1.join()
    print("Initiator thread finished...exiting")

def run_pake_session_as_responder():
    print("\t*** Running a PAKE client as responder ***")

    senderEmail = input("Please enter a sender/initiator email address:")
    receiverEmail = input("Please enter a receiver/responder email address (i.e., yours):")
    receiverPass = getpass.getpass("Please enter the receiver/responder PAKE password:")

    pakeClientA = PakeClient("A", receiverPass, senderEmail)
    pakeClientB = PakeClient("B", receiverPass, receiverEmail)

    pakeClientA.registerRemotePakeClient(pakeClientB)
    pakeClientB.registerRemotePakeClient(pakeClientA)

    pakeClientB.setup()
    
    t2 = Thread(target = pakeClientB.runSession)
    t2.start()
    
    t2.join()
    print("Responder thread finished...exiting")

def displayMainMenu():
    choice = ''
    display_title()
    while choice != 'q':
        
        choice = get_user_choice()
        
        display_title()
        if choice == '1':
            run_local_pake_test()
        elif choice == '2':
            run_pake_session_over_gmail()
        elif choice == '3':
            run_pake_session_as_initiator()
        elif choice == '4':
            run_pake_session_as_responder()
        elif choice == '5':
            pakemod.run_pure_spake2_experiment()
        elif choice == 'q':
            quit()
            print("\nThanks for the visit. Bye.")
        else:
            print("\nPlease choose a value between 1 and 5.\n")

def display_title():
    os.system('clear')
              
    print("\t*********************************************************************")
    print("\t***  PAKE-based authentication and key management run over email  ***")
    print("\t*********************************************************************")
    
def get_user_choice():
    print("\n[1] Run a local PakeMail session.")
    print("[2] Run a PakeMail session over Gmail with initiator and responder on the same machine.")
    print("[3] Run a PakeMail session as initiator over Gmail.")
    print("[4] Run a PakeMail session as responder over Gmail.")
    print("[5] Run a pure SPAKE2 session locally.")
    print("[q] Quit.")
    
    return input("Which scenario would you like to run? ")
    
def quit():
    print("\nQuitting...")

if __name__ == "__main__":
    
    displayMainMenu()

    