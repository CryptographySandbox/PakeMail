from email.mime.base import MIMEBase
from email.message import Message
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import encoders
import base64
import mimetypes
import os
import yaml
import email, smtplib, ssl
import getpass, imaplib
import gnupg
import uuid

def get_base64_file(file_path):
    with open(file_path, "rb") as f:
        b_str = base64.b64encode(f.read())
    return b_str

def get_mimetype(file_path):
    return mimetypes.guess_type(file_path)[0]

def get_file_name(file_path):
    return os.path.basename(file_path)

def writePakeMsgToFile(msg, path):
    data = dict(pakemsg=msg, side="A")
    with open('/tmp/pakemail/data.yml', 'wb') as output_file:
        yaml.dump(data, output_file)
    f = open(path, 'wb')
    f.write(msg)
    f.close()

def parsePakeMsgFromYaml(path):
    yaml_dict = dict()
    with open(path, "r") as yml_file:
        yaml_dict = yaml.load(yml_file)
    
    return yaml_dict

class PakeMail:

    def __init__(self, side, senderAddress, receiverAddress, isKeyConfirmationMsg=False):
        self.id = uuid.uuid4()
        self.side = side

        self.parentPakeClient = None

        self.message = None
        self.subject = ""

        self.pakeMailID = ""
        
        self.pakeMsgFolderPath = "/tmp/pakemail/"
        self.pakeMsgFileName = "pakemsg{0}".format(self.side)
        self.pakeMsgFilePath = "/tmp/pakemail/{0}".format(self.pakeMsgFileName)

        self.pakeMacMsgFileName = "pakemac{0}".format(self.side)
        self.pakeMacMsgFilePath = "/tmp/pakemail/{0}".format(self.pakeMacMsgFileName)

        self.senderAddress = senderAddress
        self.recipientAddress = receiverAddress
        
        if isKeyConfirmationMsg:
            self.message = self.buildMailMessage(forKeyConfirmation=True) #type email.message.Message
            self.subject = "PAKE KC email from {0} with ID: {1}".format(self.side, self.id)
        else:
            self.message = self.buildMailMessage() #type email.message.Message
            self.subject = "PAKE email from {0} with ID: {1}".format(self.side, self.id)

    def buildMailMessage(self, forKeyConfirmation=False):

        message = MIMEMultipart()
        message["From"] = self.senderAddress
        message["To"] = self.recipientAddress
        message["Subject"] = self.subject

        body = "This is an email with a PAKE message attachment from side {0} with ID: {1}.".format(self.side, self.id)

        message.attach(MIMEText(body, "plain"))

        pakeMessageFilePath = ""
        pakeMsgFileName = ""
        if forKeyConfirmation:
            pakeMessageFilePath = self.pakeMacMsgFilePath
            pakeMsgFileName = self.pakeMacMsgFileName
        else:
            pakeMessageFilePath = self.pakeMsgFilePath
            pakeMsgFileName = self.pakeMsgFileName

        with open(pakeMessageFilePath, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())

        encoders.encode_base64(part)

        part.add_header(
            "Content-Disposition",
            f"attachment; filename= {pakeMsgFileName}",
        )

        message.attach(part)

        self.message = message

        return message

    def setID(self, newID, messageType="pakeMessage"):
        self.id = newID
        if messageType == "pakeMessage":
            self.resetEmailSubject(subjectType=messageType)
        else:
            self.resetEmailSubject(subjectType="pakeMac")

    def resetEmailSubject(self, subjectType="pakeMessage"):
        if subjectType == "pakeMessage":
            self.subject = "PAKE email from {0} with ID: {1}".format(self.side, self.id)
        else:
            self.subject = "PAKE KC email from {0} with ID: {1}".format(self.side, self.id)

    def setParentPakeClient(self, pakeClient):
        self.parentPakeClient = pakeClient

    def getEmailString(self):
        if self.message == None:
            return 0
        else:
            return self.message.as_string()

    def getMessageBody(self):
        for part in self.message.walk():
            if part.get_content_type() == 'text/plain':
                return part.get_payload()

    def getPakeMsgFromAttachment(self, forKeyConfirmation=False):
        """
        docstring
        """
        if self.message == None:
            print("Email null")
            return

        pakeMessage = None
        message = self.message

        filenameMatch = ""
        if forKeyConfirmation:
            filenameMatch = "pakemac"
        else:
            filenameMatch = "pakemsg"

        for part in message.walk():
            content_disposition = str(part.get("Content-Disposition"))
            matches = ["attachment", filenameMatch]
            if all(x in content_disposition for x in matches):
                filename = part.get_filename()
                print("file name ",filename)
                if filename:
                    if not os.path.isdir(self.pakeMsgFolderPath):
                        os.mkdir(self.pakeMsgFolderPath)
                    filepath = os.path.join(self.pakeMsgFolderPath, filename)
                    
                    pakeMessage = part.get_payload(decode=True)
                    open(filepath, "wb").write(part.get_payload(decode=True))

        return pakeMessage

class PakeMailService:

    def __init__(self, pakeMail, askForPassword=True):
        self.pakeMail = pakeMail

        if askForPassword:
            self.username = input("Please enter your email username/address: ")
            self.password = getpass.getpass("Please enter your email password: ")

    def createPakeMailMessage(self, forKeyConfirmation=False):

        pakeMail = self.pakeMail

        message = MIMEMultipart()
        message["From"] = pakeMail.senderAddress
        message["To"] = pakeMail.recipientAddress
        message["Subject"] = pakeMail.subject

        body = "This is an email with a PAKE message attachment."

        message.attach(MIMEText(body, "plain"))

        pakeMessageFilePath = ""
        pakeMsgFileName = ""
        if forKeyConfirmation:
            pakeMessageFilePath = pakeMail.pakeMacMsgFilePath
            pakeMsgFileName = pakeMail.pakeMacMsgFileName
        else:
            pakeMessageFilePath = pakeMail.pakeMsgFilePath
            pakeMsgFileName = pakeMail.pakeMsgFileName

        with open(pakeMessageFilePath, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())

        encoders.encode_base64(part)

        part.add_header(
            "Content-Disposition",
            f"attachment; filename= {pakeMsgFileName}",
        )

        message.attach(part)

        return message

    def sendPakeMailMessage(self, pakeMailMessage):

        password = self.password

        sender_email = pakeMailMessage["From"]
        receiver_email = pakeMailMessage["To"]

        text = pakeMailMessage.as_string()

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, text)

    def getPakeMessageFromEmail(self, message, forKeyConfirmation=False):
        """
        docstring
        """
        if message == None:
            print("message null")
            return

        filenameMatch = ""
        if forKeyConfirmation:
            filenameMatch = "pakemac"
        else:
            filenameMatch = "pakemsg"

        for part in message.walk():
            content_disposition = str(part.get("Content-Disposition"))
            matches = ["attachment", filenameMatch]
            if all(x in content_disposition for x in matches):
                filename = part.get_filename()
                print("Downloading file:", filename)
                if filename:
                    if not os.path.isdir(self.pakeMail.pakeMsgFolderPath):
                        os.mkdir(self.pakeMail.pakeMsgFolderPath)
                    filepath = os.path.join(self.pakeMail.pakeMsgFolderPath, filename)
                    
                    pakeMessage = part.get_payload(decode=True)
                    open(filepath, "wb").write(part.get_payload(decode=True))

        return pakeMessage

    def fetchPakeEmail(self, forKeyConfirmation=False):
        
        pakeMessageFromEmail = None

        password = self.password

        email_address = self.username
        server = 'imap.gmail.com'

        mail = imaplib.IMAP4_SSL(server)
        mail.login(email_address, password)
        
        mail.select('inbox')

        # status, data = mail.search(None, 'ALL')
        status, data = mail.search(None, '(SUBJECT "PAKE")')


        mail_id_list = []
        for block in data:
            mail_id_list += block.split()

        for i in mail_id_list:
            status, data = mail.fetch(i, '(RFC822)')

            for response_part in data:
                if isinstance(response_part, tuple):
                    message = email.message_from_bytes(response_part[1])

                    # mail_from = message['from']
                    # receiver = message['to']

                    mail_subject = message['subject']
                    
                    pattern = ""
                    if forKeyConfirmation:
                        pattern = "PAKE KC email from"
                    else:
                        pattern = "PAKE email from"

                    if not(pattern in mail_subject):
                        continue

                    pakeMailID = mail_subject[mail_subject.find(":")+2:]
                    sessionHistory = self.pakeMail.parentPakeClient.sessionHistory

                    if pakeMailID in sessionHistory.keys():
                        print("Invalid session: duplicated ID!")
                        continue

                    partnerClientID = self.pakeMail.parentPakeClient.remoteClient.side
                    if (mail_subject == self.pakeMail.subject) or ("from {0}".format(self.pakeMail.side) in mail_subject) or (not("from {0}".format(partnerClientID) in mail_subject)):
                        continue

                    self.pakeMail.pakeMailID = mail_subject[mail_subject.find(":")+2:]
                    print("[{0}] extracted pake mail ID: {1}".format(self.pakeMail.side, self.pakeMail.pakeMailID))

                    if forKeyConfirmation:
                        self.pakeMail.parentPakeClient.sessionHistory[self.pakeMail.pakeMailID] = True

                    pakeMessageFromEmail = self.getPakeMessageFromEmail(message, forKeyConfirmation=forKeyConfirmation)

        return pakeMessageFromEmail