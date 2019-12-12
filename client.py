import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os

from random import random
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

from encrypt_decrypt_funcs import *
from check_validity import *
from cryptography.x509.oid import ExtensionOID, NameOID

from PyKCS11 import *
import binascii

logger = logging.getLogger('root')

STATE_CONNECT = 0       # Initial state, also assumed right after the server has been authenticated
STATE_OPEN = 1          # Assumed state when all authentication has been completed
STATE_DATA = 2          # Assumed state when sending data
STATE_CLOSE = 3         # Assumed state at the end of file transfer
STATE_CHALLENGE = 4     # Assumed state when solving a challenge
STATE_AUTH = 5          # Assumed state when authenticating Server
STATE_ACCESS_REQ = 6    # Assumed state when Requesting Authentication via Password (Access List)
STATE_CC_CHALLENGE = 7  # Assumed state when sending CC
STATE_HANDSHAKE = 7     # Assumed state when "discussing" authentication methods with server

USERNAME_PWD = 8
CC = 9

class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """

        self.file_name = file_name
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks

        self.username = 'tiago'
        self.password = 'password'
        self.auth_method = CC

        if self.auth_method == CC:
        
            lib = '/usr/local/lib/libpteidpkcs11.so'
            pkcs11 = PyKCS11.PyKCS11Lib()
            pkcs11.load(lib)
            slots = pkcs11.getSlotList()

            for slot in slots:
                pass

            all_attr = list(PyKCS11.CKA.keys())
            #Filter attributes
            all_attr = [e for e in all_attr if isinstance(e, int)]
            self.session = pkcs11.openSession(slot)
            
            for obj in self.session.findObjects():
                # Get object attributes
                attr = self.session.getAttributeValue(obj, all_attr)
                # Create dictionary with attributes
                attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
                #print(attr['CKA_CLASS'])
                if attr['CKA_CERTIFICATE_TYPE']!=None:
                    self.cert=x509.load_der_x509_certificate((bytes(attr['CKA_VALUE'])),default_backend())
                    self.cert_der = bytes(attr['CKA_VALUE'])
                    break

        with open("certs/ca_cert.pem", "rb") as ca:
            pem_data = ca.read()
            self.trusted_cas = [x509.load_pem_x509_certificate(pem_data, default_backend())]
            self.trusted_cas_b = [pem_data]


    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug('Connected to Server')
        
        self.state = STATE_HANDSHAKE
        message = {'type':'HANDSHAKE', 'method': self.auth_method}

        self._send(message)


    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
        logger.debug('Received: {}'.format(data))
        try:
            self.buffer += data.decode()
        except:
            logger.exception('Could not decode data from client')

        idx = self.buffer.find('\r\n')

        while idx >= 0:  # While there are separators
            frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
            self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find('\r\n')

        if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning('Buffer to large')
            self.buffer = ''
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
        Processes a frame (JSON Object)

        :param frame: The JSON Object to process
        :return:
        """

        #logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)

        if mtype == 'OK':  # Server replied OK. We can advance the state
            if self.state == STATE_OPEN:
                logger.info("Channel open")
                self.send_file(self.file_name)
            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                # Reserved for future use
                pass

            elif self.state == STATE_CHALLENGE: # If we solved the challenge, let's authenticate the server now
                self.challenge()
            elif self.state == STATE_HANDSHAKE:
                self.state = STATE_ACCESS_REQ
                if self.auth_method == USERNAME_PWD:
                    message = {'type':'ACCESS_REQ', 'user':'tiago'}
                else:
                    print(self.state)
                    message = {'type':'CC', 'bi':153705604, 'cert': base64.b64encode(self.cert_der).decode()}
                self._send(message)
            elif self.state == STATE_CC_CHALLENGE:
                self.challenge()
            else:
                logger.warning("Ignoring message from server")
            return

        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message.get('data', None)))

        elif mtype == 'CHALLENGE_REQ':
            # The client is gonna reply with a hash/password + NONCE)
            rand_val = message['value']
            hash_func = message['hash_func']
            if hash_func == 'SHA-256':
                val = sintese('SHA-256', (rand_val + sintese( 'SHA-512', self.password.encode())).encode())
            elif hash_func == 'SHA-512':
                val = sintese('SHA-512', (rand_val + sintese( 'SHA-512', self.password.encode())).encode())
            else:
                logger.error('Unsupported Hash Function')
                self.transport.close()
                return

            reply = {
                       'type':'CHALLENGE_REP',
                       'val': val
                    }
            
            self.state = STATE_CHALLENGE
            self._send(reply)
            return

        elif mtype == 'CERT':

            ## Validate the cert received
            server_cert_b = base64.b64decode(message['server_cert'].encode())
            server_cert = x509.load_pem_x509_certificate(server_cert_b, default_backend())
            server_key = load_pem_public_key(base64.b64decode(message['server_key'].encode()), backend=default_backend())
            flag = False
            
            ## Check if is within viable date
            if not check_validity_content(server_cert_b):
                logger.error("Server certificate validity date isn't valid")
                self.transport.close()
                return False
            

            ## Check cert issuer
            if server_cert.issuer != self.trusted_cas[0].issuer:

                ## In a real world scenario, we would here make a recursive call for more certs
                logger.error("Invalid issuer")
                logger.debug(server_cert.issuer)
                logger.debug(self.trusted_cas[0].issuer)
                self.transport.close()
                return False


            ## Here, we know that the server_cert.issuer is self.trusted_cas[0], so we can treat each one of them de forma indistinta
            ## Check if issuer is a CA, basic constraint
            for ext in self.trusted_cas[0].extensions:
                if(ext.value.ca):
                    logger.debug("Server certificate was issued by a CA")
                    flag = True

            if not flag:
                logger.error("Server certificate wasn't issued by a Certification Authority")
                self.transport.close()
                return False


            ## Check cert signature
            issuer_public_key = load_pem_public_key(self.trusted_cas[0].public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo), default_backend())
            cert_to_check = x509.load_pem_x509_certificate(server_cert_b, default_backend())
            issuer_public_key.verify(
                cert_to_check.signature,
                cert_to_check.tbs_certificate_bytes,
                # Depends on the algorithm used to create the certificate
                padding.PKCS1v15(),
                cert_to_check.signature_hash_algorithm,
            )


            ## Check if name on cert matches name of the server
            if server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != message['server_name']:
                print(server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME[0]))
                logger.error("Invalid name")
                self.transport.close()                
                return False

            
            ## Validate if our CA is still a CA, if it's still valid within our date and if it isn't in its own CRL
            if not check_validity_content(self.trusted_cas_b[0]):
                logger.error("Our trusted CA isn't trustworthy anymore. Trust no one.")
                self.trusted_cas.pop(0)
                self.trusted_cas_b.pop(0)
                self.transport.close()
                return False

            flag = False
            # In this case, we are validating self.trusted_cas[0] as our trusted CA, and not as an issuer
            for ext in self.trusted_cas[0].extensions:
                if(ext.value.ca):
                    flag = True

            if not flag:
                logger.error("Our trusted CA isn't trustworthy anymore. Trust no one.")
                self.trusted_cas.pop(0)
                self.trusted_cas_b.pop(0)
                self.transport.close()
                return False

            
            


            logger.debug("Server validated")

            # Once the server has been validated, we can proceed to the file transfer
            message = {'type': 'OPEN', 'file_name': self.file_name}
            self._send(message)
            self.state = STATE_OPEN
            return

        
        elif mtype == 'CHALLENGE_CC':
            nonce = message['nonce']
            # sign nonce
            private_key = self.session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
            ])[0]

            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
            signature = bytes(self.session.sign(private_key, nonce, mechanism))
            # send signed nonce
            message = {'type':'SIGNATURE', 'signature':base64.b64encode(signature).decode()}
            
            self.state = STATE_CHALLENGE
            self._send(message)

            # await for ok
            return


        else:
            logger.warning("Invalid message type")

        self.transport.close()
        self.loop.stop()

    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info('The server closed the connection')
        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """

        with open(file_name, 'rb') as f:
            message = {'type': 'DATA', 'data': None}
            read_size = 16 * 60
            while True:
                data = f.read(16 * 60)
                message['data'] = base64.b64encode(data).decode()
                self._send(message)

                if len(data) != read_size:
                    break

            self._send({'type': 'CLOSE'})
            logger.info("File transferred. Closing transport")
            self.transport.close()

    
    def challenge(self):
        message = {'type':'CERT_REQ'}
        self._send(message)
        self.state = STATE_AUTH


    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
        logger.debug("Send: {}".format(message))

        message_b = (json.dumps(message) + '\r\n').encode()
        self.transport.write(message_b)


def main():
    parser = argparse.ArgumentParser(description='Sends files to servers.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p', type=int, nargs=1,
                        dest='port', default=5000,
                        help='Server port (default=5000)')

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    main()