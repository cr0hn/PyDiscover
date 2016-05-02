import os
import json
import asyncio
import logging
import argparse
import datetime
import configparser

from pydiscover.utils import prepare_text, crypt, decrypt
from socket import gethostbyname, gethostname

logging.basicConfig(level=logging.INFO, format='[ %(levelname)-5s - Service Discovery ] %(asctime)s - %(message)s')
log = logging.getLogger(__name__)


class DiscoverServerProtocol:

	magic = None
	my_ip = None
	password = None
	answer = None
	disable_hidden = False

	def connection_made(self, transport):
		self.transport = transport

	def datagram_received(self, data, addr):
		message = decrypt(data, self.password)

		# Get a correlates query
		if message.startswith(self.magic):

			# Check timestamp and if there's more than 20 second between send -> not response
			try:
				timestamp = float(message[len(self.magic):])
			except TypeError:
				log.debug('Received invalid timestamp in package from %s' % ("%s:%s" % addr))
				if self.disable_hidden:
					self.transport.sendto(crypt("%s#ERROR#%s" % (self.magic, "Invalid timestamp"), self.password), addr)
				return

			# Check if packet was generated before 20 seconds
			if datetime.datetime.fromtimestamp(timestamp) < (datetime.datetime.now() - datetime.timedelta(seconds=20)):
				if self.disable_hidden:
					self.transport.sendto(crypt("%s#ERROR#%s" % (self.magic, "Timestamp is too old"), self.password), addr)
				log.debug('Received outdated package from %s' % ("%s:%s" % addr))
				return

			# Timestamp is correct -> continue
			log.debug('Received %r from %s' % (message, "%s:%s" % addr))

			self.transport.sendto(crypt("%s#OK#%s" % (self.magic, self.answer), self.password), addr)
		else:
			if self.disable_hidden:
				self.transport.sendto(("%s#ERROR#%s" % (self.magic, "Invalid MAGIC or Password")).encode(), addr)
			log.debug('Received bad magic or password from %s:%s' % addr)


def server_discover(answer, magic="fna349fn", listen_ip="0.0.0.0", port=50000, password=None, disable_hidden=False):

	my_ip = gethostbyname(gethostname())

	log.info("Starting discover server")

	# Prepare password
	if password:
		password = prepare_text(password)

	# Load the answer as JSON
	config = configparser.ConfigParser()
	config.read_file(open(answer))
	_answer = json.dumps(dict(config["DEFAULT"]))

	# Setup Protocol
	DiscoverServerProtocol.magic = magic
	DiscoverServerProtocol.my_ip = my_ip
	DiscoverServerProtocol.password = password
	DiscoverServerProtocol.disable_hidden = disable_hidden
	DiscoverServerProtocol.answer = _answer

	# Start running
	loop = asyncio.get_event_loop()

	listen = loop.create_datagram_endpoint(DiscoverServerProtocol,
	                                       local_addr=(listen_ip, port),
	                                       allow_broadcast=True)
	transport, protocol = loop.run_until_complete(listen)

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass
	finally:
		log.info("Shutdown server")
		transport.close()
		loop.close()


def main():

	example = """
Examples:

	Put server to listen and return the Service Register Server IP:
	%(name)s -d 10.0.0.1

	Put server listen and return various Services Registers Servers:
	%(name)s -d 10.0.0.1,192.168.1.1

	Increase verbosity:
	%(name)s -vvv -d 10.0.0.1

	Securing channel communication setting a password:
	%(name)s -vvv -d 10.0.0.1 --password "lasi)8sn;k18s7hfalsk"

	Changing channel port:
	%(name)s -vvv -d 10.0.0.1 -p 91882 --password "lasi)8sn;k18s7hfalsk"

	Changing the MAGIC:
	%(name)s -vvv -m Iksjj19k2j -d 10.0.0.1 -p 91882 --password "lasi)8sn;k18s7hfalsk"

	Disabling hidden mode:
	%(name)s -vvv --disable-hidden -m Iksjj19k2j -d 10.0.0.1 -p 91882 --password "lasi)8sn;k18s7hfalsk"

* MAGIC:

The MAGIC is a string that defines an internal "channel". Client and server must known the channel. The server only
responds to the clients with known this MAGIC.

* Hidden mode:

By default, the server doesn't response to the clients with ack with and invalid MAGIC, PASSWORD or messages that was
sent more than 20 seconds before the server receive it. If we disable the hidden mode, server will respond this the
appropriate error to the client.
	""" % dict(name="discovery-server")

	parser = argparse.ArgumentParser(description='PyDiscover Server',
	                                 formatter_class=argparse.RawTextHelpFormatter, epilog=example)

	# Main options
	parser.add_argument('-d', '--discover-info', dest="INFO", help="file with info to send to the clients",
	                    required=True)
	parser.add_argument("-v", "--verbosity", dest="VERBOSE", action="count", help="verbosity level: -v, -vv, -vvv.",
	                    default=3)

	gr_options = parser.add_argument_group("more options")
	parser.add_argument('-m', '--magic', dest="MAGIC", help="preamble for streams.", default="fna349fn")
	gr_options.add_argument('--password', dest="PASSWORD", help="server access password. Default None", default=None)
	parser.add_argument('-p', '--port', dest="PORT", type=int, help="listen port. Default 50000", default=50000)
	parser.add_argument('-l', '--listen', dest="IP", help="listen IP. Default 0.0.0.0", default="0.0.0.0")
	parser.add_argument('--disable-hidden', dest="NO_HIDDEN", action="store_true", help="disable hidden mode", default=False)

	parsed_args = parser.parse_args()

	# Setting
	log.setLevel(abs(50 - (parsed_args.VERBOSE * 10)))

	# Call server
	server_discover(answer=parsed_args.INFO,
	                magic=parsed_args.MAGIC,
	                listen_ip=parsed_args.IP,
	                port=parsed_args.PORT,
	                password=parsed_args.PASSWORD,
	                disable_hidden=parsed_args.NO_HIDDEN)

if __name__ == '__main__':
	main()
