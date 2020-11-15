# PakeMail

* License: [MIT](LICENSE)
* Dependencies: Python-SPAKE2, PyNaCl, python-gnupg
* Compatible with: Python 3.6

PakeMail is a proof of concept Python implementation of the core ideas described in our [SECRYPT 2020 paper](https://arxiv.org/pdf/2005.10787.pdf) aimed at carrying out a password-authenticated key exchange (PAKE) protocol in a decentralized setting for authenticating public keys and establishing a shared symmetric cryptographic key, using standard email and attachments as transport mechanism for networking, while preserving interoperability and without introducing any extra trust assumptions.

In its current form, this implementation should be considered as a proof of concept and should not be used for serious security purposes.

The current implementation is geared towards Unix-like operating systems, but it can be easily ported to other platforms.


## Installation

1. Clone the repository
```sh
git clone https://
```

2. Use the package manager `pip` to install the dependencies

```bash
$pip install -r requirements.txt
```

We recommend using a Python virtual environment for an isolated installation, independent from your system-wide Python configuration. For instance, you could do so using [Anaconda](https://www.anaconda.com/products/individual):
```sh
$conda create --name <ENV_NAME> python=3.6
$conda activate <ENV_NAME> 
$pip install -r requirements.txt
```

## Usage

### Built-in executable scenarios

The PakeMail implementation comes with a set of PAKE scenarios executable from a console menu, which can be accessed as follows:

```bash
$python PakeMail_sandbox.py
```

The current scenarios include:

1. A local execution of two independent threads of PAKE clients running a PAKE session with key confirmation, followed by some cryptographic tasks using the established key.

2. An online execution of two PAKE instances (an initiator and a responder) running on the same machine but routing their messages via email exchanges and attachments. The same email address can be used for the initiator and the responder. For instance, using Gmail, one can simply add identifiers to an existing Gmail address using the "+" sign, e.g., test+senderA@gmail.com and test+receiverB@gmail.com for the same test@gmail.com address.

3. Run an initiator PakeMail instance one one machine that will use Gmail as transport mechanism to run a PAKE session with a desiganted responder instance.

4. Run a responder PakeMail instance one one machine that will use Gmail as transport mechanism to run a PAKE session with a desiganted initiator instance.

5. Automatic execution of performance tests for the underlying SPAKE2 library, using four different security parameters (see below "Cryptographic details"). Note: this is rather redundant as the same functionality is already available in the SPAKE2 library.

The two scenarios (3) and (4) are meant to be run together on different machines, to recreate a remote authentication scenario where the initiator and the responder end up sharing a high-entropy symmetric secret key, authenticated by a low-entropy password, e.g., "PakeMail".

All scenarios provide execution time information upon termination. Note that the currently used aritifical delays between fetching queries (mainly to avoid frequent queries) are not included in the timing information.

These scenarios currently work with Gmail. Using other services is possible by modifying the corresponding mail server information in the functions `sendPakeMailMessage` and `fetchPakeEmail` located in the file [pakemail.py](src/pakemail.py).

## Caveats

### GPG

For a given email address, the current implementation by default tries to retrieve the corresponding public key fingerprint from an existing GPG installation. Therefore, if you use an email address for which you already have existing key pairs, make sure they are available on both machines (this will be sorted out in a future update :-)). In case zero or more than one fingerprints are retrieved, the code falls back to two default hardcoded values, which have been added for testing purposes. This last option is the recommended choice for now.

## Previous session emails

In the current version, due to a known bug, when it comes to running scenarios (3) and (4) together, we recommend deleting the 4 session messages created in the mailbox before running another instance. This will be fixed soon.

### Using PakeMail as a library

To be added soon...

## General info

This proof of concept was developed by Arash Atashpendar and Itzel Vazquez Sandoval in November 2020.