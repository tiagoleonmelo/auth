import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import re
import os
import secrets
from aio_tcpserver import tcp_server
from encrypt_decrypt_funcs import *

from random import random
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE= 3
STATE_CHALLENGE = 4
STATE_AUTH = 5

USERNAME_PWD = 8
CC = 9

#GLOBAL
storage_dir = 'files'

class ClientHandler(asyncio.Protocol):
	def __init__(self, signal):
		"""
		Default constructor
		"""
		self.signal = signal
		self.state = 0
		self.file = None
		self.file_name = None
		self.file_path = None
		self.storage_dir = storage_dir
		self.buffer = ''
		self.peername = ''
		

		# user : hashed_user_password
		self.hashed_list = {'tiago':'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86'}
		# access list that contains the usernames allowed to interact with the system
		self.access_list = ['tiago']

		c = open("certs/server_cert.pem", "rb")
		pem_data = c.read()
		self.cert = x509.load_pem_x509_certificate(pem_data, default_backend())
		c.close()

		self.auth_method = None
		self.name = 'My Server'

	def connection_made(self, transport) -> None:
		"""
		Called when a client connects

		:param transport: The transport stream to use with this client
		:return:
		"""
		self.peername = transport.get_extra_info('peername')
		logger.info('\n\nConnection from {}'.format(self.peername))
		self.transport = transport


	def data_received(self, data: bytes) -> None:
		"""
        Called when data is received from the client.
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
		Called when a frame (JSON Object) is extracted

		:param frame: The JSON object to process
		:return:
		"""
		#logger.debug("Frame: {}".format(frame))

		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode JSON message: {}".format(frame))
			self.transport.close()
			return

		mtype = message.get('type', "").upper()

		if mtype == 'OPEN':
			ret = self.process_open(message)
		elif mtype == 'DATA':
			ret = self.process_data(message)
		elif mtype == 'CLOSE':
			ret = self.process_close(message)
		elif mtype == 'CHALLENGE_REP':
			ret = self.process_challenge(message)
		elif mtype == 'CERT_REQ':
			ret = self.reply_to_challenge(message)
		elif mtype == 'ACCESS_REQ':
			ret = self.process_access(message)
		elif mtype == 'HANDSHAKE':
			ret = self.process_handshake(message)
		else:
			logger.warning("Invalid message type: {}".format(message['type']))
			ret = False

		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'See server'})
			except:
				pass # Silently ignore

			logger.info("Closing transport")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()


	def process_open(self, message: str) -> bool:
		"""
		Processes an OPEN message from the client
		This message should contain the filename

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Open: {}".format(message))

		if self.state != STATE_CONNECT:
			logger.warning("Invalid state. Discardinggg")
			return False

		if not 'file_name' in message:
			logger.warning("No filename in Open")
			return False

		if self.username not in self.access_list:
			logger.error("Permission denied - User %s not in access list; can't transfer files" % self.username)
			return False

		# Only chars and letters in the filename
		file_name = re.sub(r'[^\w\.]', '', message['file_name'])
		file_path = os.path.join(self.storage_dir, file_name)
		if not os.path.exists("files"):
			try:
				os.mkdir("files")
			except:
				logger.exception("Unable to create storage directory")
				return False

		try:
			self.file = open(file_path, "wb")
			logger.info("File open")
		except Exception:
			logger.exception("Unable to open file")
			return False

		self._send({'type': 'OK'})

		self.file_name = file_name
		self.file_path = file_path
		self.state = STATE_OPEN
		return True


	def process_data(self, message: str) -> bool:
		"""
		Processes a DATA message from the client
		This message should contain a chunk of the file

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Data: {}".format(message))

		if self.state == STATE_OPEN:
			self.state = STATE_DATA
			# First Packet

		elif self.state == STATE_DATA:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		try:
			self.file.write(bdata)
			self.file.flush()
		except:
			logger.exception("Could not write to file")
			return False

		return True


	def process_close(self, message: str) -> bool:
		"""
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Close: {}".format(message))

		self.transport.close()
		if self.file is not None:
			self.file.close()
			self.file = None

		self.state = STATE_CLOSE

		return True

	
	def process_challenge(self, message: str) -> None:
		"""
		Processes a challenge reply. Replies with okay if everything checks out
		:param message:
		:return:
		"""
		value = message.get('val', None)

		if value != self.challenge_ans:
			logger.error("Authentication failed")
			return False
		

		self.state = STATE_AUTH
		self._send({'type':'OK'})

		return True


	def reply_to_challenge(self, message: str) -> None:
		# Sign the challenge and send it back to the client

		reply = {
					'type':'CERT',
					'server_cert':base64.b64encode(self.cert.public_bytes(Encoding.PEM)).decode(),
					'server_key':base64.b64encode(self.cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)).decode(),
					'server_name':self.name
				}
		
		self._send(reply)
		self.state = STATE_CONNECT
		return True


	def process_access(self, message: str) -> None:
		self.username = message['user']

		pwd = self.hashed_list.get(self.username, None)
		
		if not pwd:
			logger.error("User not in Database, terminating")
			return False

		# Send him a timestamp and a rand value for him to return the hash(password+timestamp+rand)
		self.challenge = str(datetime.now()) + str(random())
		self.challenge_ans = sintese('SHA-512', (self.challenge + pwd).encode())

		message = {'type':'CHALLENGE_REQ', 'value':self.challenge, 'hash_func':'SHA-512'}

		self._send(message)
		self.state = STATE_AUTH
		return True


	def process_handshake(self, message: str) -> None:
		auth_method = message.get('method', None)
		message = {'type':'OK'}

		if auth_method:
			if auth_method == USERNAME_PWD:
				self.auth_method = USERNAME_PWD
				self._send(message)
				return True

			elif auth_method == CC:
				self.auth_method = CC
				self._send(message)		
				return True

		return False


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
	global storage_dir

	parser = argparse.ArgumentParser(description='Receives files from clients.')
	parser.add_argument('-v', action='count', dest='verbose',
						help='Shows debug messages (default=False)',
						default=0)
	parser.add_argument('-p', type=int, nargs=1,
						dest='port', default=5000,
						help='TCP Port to use (default=5000)')

	parser.add_argument('-d', type=str, required=False, dest='storage_dir',
						default='files',
						help='Where to store files (default=./files)')

	args = parser.parse_args()
	storage_dir = os.path.abspath(args.storage_dir)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO
	port = args.port
	if port <= 0 or port > 65535:
		logger.error("Invalid port")
		return

	if port < 1024 and not os.geteuid() == 0:
		logger.error("Ports below 1024 require eUID=0 (root)")
		return

	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Port: {} LogLevel: {} Storage: {}".format(port, level, storage_dir))
	tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == '__main__':
	main()


