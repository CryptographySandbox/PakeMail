from spake2 import SPAKE2_A
from spake2 import SPAKE2_B
from spake2.parameters.i1024 import Params1024
from spake2.parameters.i2048 import Params2048
from spake2.parameters.i3072 import Params3072
import base64
import enum
import os
import yaml
from pakemail import PakeMail, PakeMailService
from hkdf import hkdf_extract, hkdf_expand
import hashlib
import hmac
import uuid
import time, timeit
import nacl.utils
import pickle
import gnupg

def getGpgHandler():
    gpgPath=str(os.path.expanduser("~"))+"/.gnupg"
    if not os.path.isdir(gpgPath):
        os.mkdir(gpgPath)

    expPath = gpgPath + "exported/"
    if not os.path.isdir(expPath):
        os.mkdir(expPath)
                        
    gpg = gnupg.GPG(gnupghome=gpgPath)
    gpg.encoding = 'utf-8'
    return gpg

def getKeyFingerprintFromGpg(byEmail=""):
    gpg = getGpgHandler()
    key_list = gpg.list_keys()
    match_list = []
    for l in key_list:
        for e in (l['uids']):
            if byEmail in e:
                fingerprint = l['fingerprint']
                match_list.append(fingerprint)
    
    return match_list

def writePakeMsgToFile(msg, client_side, path):
    f = open(path, 'wb')
    f.write(msg)
    f.close()

class Roles(enum.Enum):
    A = "A"
    B = "B"

class Parameters(enum.Enum):
    p1024 = Params1024
    p2048 = Params2048
    p3072 = Params3072

class PakeClient:

    def __init__(self, side, password, email, parameters=None):
        self.side = side
        self.password = password

        self.spake = None
        self.key = None
        
        self.email = email
        self.remoteClient = None

        self.sessionHistory = dict()
        
        # only for testing; will be replaced by the call to getPublicKeyFingerprint()
        self.pkAfpr = "BD5F3D50B81B4D471F95EFAD00809FFA6F62F85C"
        # only for testing; will be replaced by the call to getPublicKeyFingerprint()
        self.pkBfpr = "D2E67C6882F939704A2366E9F2256109C435AC2D"

        self.pakeMessage = None
        self.pakeMail = None
        self.pakeMailService = None

        self.remoteClientPakeMessage = None

        self.tauA = None
        self.expectedTauA = None
        self.tauB = None
        self.expectedTauB = None

        self.transcript = None

        self.parameters = parameters

        self.executionTime = float(0)
        self.emailFetchWaitTime = 0

        self.pakeMsgFolderPath = "/tmp/pakemail/"
        self.pakeMsgFileName = "pakemsg{0}".format(self.side)
        self.pakeMsgFilePath = "/tmp/pakemail/{0}".format(self.pakeMsgFileName)

        self.pakeMacMsgFileName = "pakemac{0}".format(self.side)
        self.pakeMacMsgFilePath = "/tmp/pakemail/{0}".format(self.pakeMacMsgFileName)
        
        idA_bytes = bytes(Roles.A.value, encoding='utf-8')
        idB_bytes = bytes(Roles.B.value, encoding='utf-8')
        if side == Roles.A.value:
            self.pake = SPAKE2_A(idA=idA_bytes, idB=idB_bytes, password=bytes(password, encoding='utf-8'))
        else:
            self.pake = SPAKE2_B(idA=idA_bytes, idB=idB_bytes, password=bytes(password, encoding='utf-8'))


    def setup(self, localTest=False):
        start = time.process_time()

        sender = self.email
        receiver = self.remoteClient.email

        self.readSessionHistoryIntoMemory()

        self.createInitMsg(writeToFile=True)

        self.pakeMail = PakeMail(self.side, sender, receiver)

        self.pakeMail.setParentPakeClient(pakeClient=self)

        self.executionTime += (time.process_time() - start)

        # for case 1 in the initial menu, as the values are hardcoded
        if localTest:
            self.pakeMailService = PakeMailService(self.pakeMail, askForPassword=False)
            self.pakeMailService.password = self.password
        else:
            self.pakeMailService = PakeMailService(self.pakeMail)
        self.pakeMailService.username = self.email
    
    def createInitMsg(self, writeToFile=False):
        self.pakeMessage = self.pake.start()
        
        if writeToFile:
            if not os.path.isdir(self.pakeMsgFolderPath):
                os.mkdir(self.pakeMsgFolderPath)
            
            writePakeMsgToFile(self.pakeMessage, self.side, self.pakeMsgFilePath)

        return self.pakeMessage

    def createMacMsg(self, mac, writeToFile=False):
        if self.key == None:
            print("No key available...")
            return None
        
        if writeToFile:
            if not os.path.isdir(self.pakeMsgFolderPath):
                os.mkdir(self.pakeMsgFolderPath)
            
            writePakeMsgToFile(mac, self.side, self.pakeMacMsgFilePath)
        
        pakeMessageMail = self.pakeMail
        self.pakeMail = PakeMail(self.side, pakeMessageMail.senderAddress, pakeMessageMail.recipientAddress, isKeyConfirmationMsg=True)
        self.pakeMail.setID(pakeMessageMail.id, messageType="pakeMac")
        self.pakeMail.setParentPakeClient(pakeClient=self)

        pakeMailService = self.pakeMailService
        self.pakeMailService = PakeMailService(self.pakeMail, askForPassword=False)
        self.pakeMailService.username = pakeMailService.username
        self.pakeMailService.password = pakeMailService.password

    def computeKey(self,pake_msg):
        self.remoteClientPakeMessage = pake_msg
        self.key = self.pake.finish(pake_msg)

    def registerRemotePakeClient(self, remoteClient):
        self.pkAfpr = self.getPublicKeyFingerprint(email=self.email)
        print("[A] retrieved PK fingerprint: {0}".format(self.pkAfpr))

        self.pkBfpr = self.getPublicKeyFingerprint(email=remoteClient.email)
        print("[B] retrieved PK fingerprint: {0}".format(self.pkBfpr))

        self.remoteClient = remoteClient

    def writeSessionHistoryToFile(self):
        file = open("/tmp/pakemail/session_history{0}.txt".format(self.side), "wb") 

        pickle.dump(self.sessionHistory, file) 

        file.close()

    def readSessionHistoryIntoMemory(self):

        if not os.path.isfile("/tmp/pakemail/session_history{0}.txt".format(self.side)):
            return

        with open("/tmp/pakemail/session_history{0}.txt".format(self.side), 'rb+') as handle: 
            data = handle.read() 

        self.sessionHistory = pickle.loads(data)

    def getPublicKeyFingerprint(self, email=""):
        fpr = getKeyFingerprintFromGpg(byEmail=email)
        if len(fpr) == 0 or len(fpr) > 1:
            print("Either no key pair available or there's more than one... returning a fixed value for testing purposes.")
            return "BD5F3D50B81B4D471F95EFAD00809FFA6F62F85C"
        else:
            return str(fpr[0])

    def computeTranscript(self):
        if self.side == Roles.A.value:
            self.transcript = self.pkAfpr+self.pkBfpr+"A"+"B"+str(self.pakeMessage)+str(self.remoteClientPakeMessage)
        else:
            self.transcript = self.pkBfpr+self.pkAfpr+"A"+"B"+str(self.remoteClientPakeMessage)+str(self.pakeMessage)
        print("[{0}] transcript: {1}".format(self.side, self.transcript))

    def runKeyDerivation(self):
        sessionKey = hkdf_expand(self.key, b"session key", 32)
        macKeyA = hkdf_expand(self.key, b"MAC key A", 16)
        macKeyB = hkdf_expand(self.key, b"MAC key B", 16)

        return sessionKey, macKeyA, macKeyB

    def computeMAC(self, macKey, message):
        return hmac.new(macKey, message.encode('utf-8'), hashlib.sha256).digest()

    def sendPakeMessage(self, forKeyConfirmation=False):
        if self.remoteClient == None:
            print("No remote PAKE client set up.")
            return None

        self.pakeMailService.sendPakeMailMessage(self.pakeMailService.createPakeMailMessage(forKeyConfirmation=forKeyConfirmation))

    def runSession(self):
        start = time.process_time()

        if self.side == Roles.A.value:
            # Send pake message to the responder PAKE client
            self.sendPakeMessage()

            # Periodically fetch for reply PAKE messages until one found
            pakeMessageFromRemote = None
            while (pakeMessageFromRemote == None):
                self.emailFetchWaitTime += 3
                time.sleep(3)
                print("Initiator fetching PAKE message...")
                pakeMessageFromRemote = self.pakeMailService.fetchPakeEmail()
        else:
            # Periodically fetch for reply PAKE messages until one found
            pakeMessageFromRemote = None
            while (pakeMessageFromRemote == None):
                self.emailFetchWaitTime += 3
                time.sleep(3)
                print("Responder fetching PAKE message...")
                pakeMessageFromRemote = self.pakeMailService.fetchPakeEmail()

            self.pakeMail.setID(self.pakeMail.pakeMailID, "pakeMac")
            self.pakeMail.setID(self.pakeMail.pakeMailID, "pakeMessage")

            # Send pake message to the initiator PAKE client
            self.sendPakeMessage()
            
        # Compute the intermediate secret key
        self.computeKey(pakeMessageFromRemote)
        print("\nThe intermediate key of {0} is:\n{1}\n".format(self.side, self.key))

        # Key confirmation starts here
        k, macKeyA, macKeyB = self.runKeyDerivation()
        self.computeTranscript()
        macMessage = self.transcript
        
        if self.side == Roles.A.value:
            self.tauA = self.computeMAC(macKeyA, macMessage)
            self.createMacMsg(self.tauA, writeToFile=True)
            self.expectedTauB = self.computeMAC(macKeyB, macMessage)
        else:
            self.tauB = self.computeMAC(macKeyB, macMessage)
            self.createMacMsg(self.tauB, writeToFile=True)
            self.expectedTauA = self.computeMAC(macKeyA, macMessage)

        self.sendPakeMessage(forKeyConfirmation=True)
        
        # Periodically fetch for reply PAKE KC messages until one found
        pakeMessageFromRemote = None
        while (pakeMessageFromRemote == None):
            self.emailFetchWaitTime += 3
            time.sleep(3)
            print("{0} fetching KC message...".format(self.side))
            pakeMessageFromRemote = self.pakeMailService.fetchPakeEmail(forKeyConfirmation=True)

        print("{0} received tau:\n{1}".format(self.side, pakeMessageFromRemote))

        if self.side == Roles.A.value:
            print("{0} comparing tags\n{1}\n{2}: ".format(self.side, self.expectedTauB, pakeMessageFromRemote))
            print("Tags match on A side: ", self.expectedTauB == pakeMessageFromRemote)
        else:
            print("{0} comparing tags\n{1}\n{2}: ".format(self.side, self.expectedTauA, pakeMessageFromRemote))
            print("Tags match on B side: ", self.expectedTauA == pakeMessageFromRemote)

        print("Final secret key on {0} side is: ".format(self.side), k)

        self.writeSessionHistoryToFile()

        self.executionTime += (time.process_time() - start)

        return self.key
        
def run_pure_spake2_experiment(verbose=False):
    executionTime = float(0)
    start = time.process_time()

    password=b"pass"

    parameters = ["Params1024", "Params2048", "Params3072", ""]

    round_count = 50
    for param in parameters:
        total_execution_time = float(0)

        if (param=="Params1024"):
            selected_param=Params1024
        if (param=="Params2048"):
            selected_param=Params2048
        if (param=="Params3072"):
            selected_param=Params3072
        if param=="":
            selected_param=""
        
        if selected_param == "":
            print("Selected security level: Curve25519")
        else:
            print("Selected security level:", param)

        for _ in range(1, round_count):
            executionTime = float(0)
            start = time.process_time()

            if selected_param == "":
                alice = SPAKE2_A(password)
                bob = SPAKE2_B(password)
            else:
                alice = SPAKE2_A(password,params=selected_param)
                bob = SPAKE2_B(password,params=selected_param)
                
            alice_out = alice.start()
            bob_out = bob.start()

            if verbose:
                print("\nAlice sends:\t",base64.b64encode(alice_out))
                print("Bob sends:\t",base64.b64encode(bob_out))

            keyA = alice.finish(bob_out)
            keyB = bob.finish(alice_out)

            if verbose:
                print("\nKey (Alice):\t",base64.b64encode(keyA))
                print("Key (Bob):\t",base64.b64encode(keyB))
                print("Derived keys equal?",base64.b64encode(keyA)==base64.b64encode(keyB))

            executionTime = (time.process_time() - start)
            total_execution_time += executionTime
            print("Individual experiment execution time: ", executionTime)
        
        print("Average execution time: ", total_execution_time/round_count)
        print("-------------------------------------------")

if __name__ == "__main__":
    run_pure_spake2_experiment()