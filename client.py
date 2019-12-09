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

logger = logging.getLogger('root')

STATE_CONNECT = 0       # Initial state, also assumed right after the server has been authenticated
STATE_OPEN = 1          # Assumed state when all authentication has been completed
STATE_DATA = 2          # Assumed state when sending data
STATE_CLOSE = 3         # Assumed state at the end of file transfer
STATE_CHALLENGE = 4     # Assumed state when solving a challenge
STATE_AUTH = 5          # Assumed state when authenticating Server
STATE_ACCESS_REQ = 6    # Assumed state when Requesting Authentication via Password (Access List)
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
        self.auth_method = USERNAME_PWD

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug('Connected to Server')
        
        self.state = STATE_HANDSHAKE
        message = {'type':'HANDSHAKE', 'method':self.auth_method}

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
                    message = {'type':'CC', 'value':'idk'}
                self._send(message)
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

        elif mtype == 'CHALLENGE_REP':

            signature = base64.b64decode(message['signature'].encode())
            server_pub_key = load_pem_public_key(base64.b64decode(message['public_key'].encode()), backend=default_backend())

            server_pub_key.verify(
                signature,
                self.value.encode(),
                padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ), hashes.SHA256())

            # Program will crash if verify doesn't work
            logger.debug('Signature validated.')


            # Once the server has been validated, we can proceed to the file transfer
            message = {'type': 'OPEN', 'file_name': self.file_name}
            self._send(message)
            self.state = STATE_OPEN
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
        self.value = str(datetime.now()) + str(random())
        message = {'type':'CHALLENGE_REQ', 'value':self.value}

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