import json
import socket
import logging
import argparse
import datetime

from pydiscover.utils import prepare_text, crypt, decrypt

logging.basicConfig(level=logging.INFO, format='[%(levelname)s - Client Discovery ] %(asctime)s - %(message)s')
log = logging.getLogger(__name__)


#
# This code is based in: http://stackoverflow.com/a/21090815
#

class TimeStampException(Exception):
	pass


class PasswordMagicException(Exception):
	pass


class TimeOutException(Exception):
	pass


def discover(magic="fna349fn", port=50000, password=None, timeout=5):
	log.info("Looking for a server discovery")

	# Prepare password
	if password:
		password = prepare_text(password)

	# Build message
	msg = "%s%s" % (magic, datetime.datetime.now().timestamp())

	try:
		# Send discover
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # create UDP socket
		s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # this is a broadcast socket
		s.sendto(crypt(msg, password), ('<broadcast>', port))
		s.settimeout(timeout)

		data, addr = s.recvfrom(1024)  # wait for a packet
	except socket.timeout:
		log.info("No servers found")

		raise TimeOutException("No servers found")

	msg = decrypt(data, password)

	# Get a correlates response
	if msg.startswith(magic):
		msg_details = msg[len(magic):]

		log.debug("Got service announcement from '%s' with response: %s" % ("%s:%s" % addr, msg_details))

		if msg_details.startswith("#ERROR#"):
			error_details = msg_details[len("#ERROR#"):]

			log.debug("Response from server: %s" % error_details)

			if "timestamp" in error_details:
				raise TimeStampException(error_details)
			elif "password" in error_details:
				raise PasswordMagicException(error_details)
		else:
			undecoded_msg = msg_details[len("#OK#"):]

			# Decode the json
			ok_details = json.loads(undecoded_msg)

			return ok_details, "%s:%s" % addr


def main():
	parser = argparse.ArgumentParser(description='PyDiscover Client',
	                                 formatter_class=argparse.RawTextHelpFormatter)

	# Main options
	parser.add_argument('-m', '--magic', dest="MAGIC", help="preamble for streams.", default="fna349fn")
	parser.add_argument('-p', '--port', dest="PORT", type=int, help="listen port. Default 50000", default=50000)
	parser.add_argument("-v", "--verbosity", dest="VERBOSE", action="count", help="verbosity level: -v, -vv, -vvv.",
	                    default=2)

	gr_options = parser.add_argument_group("more options")

	gr_options.add_argument('-t', '--timeout', dest="TIMEOUT", type=int,
	                        help="timeout to wait for a server. Default 5s",
	                        default=5)
	gr_options.add_argument('--password', dest="PASSWORD", help="server access password. Default None", default=None)

	parsed_args = parser.parse_args()

	# Setting
	log.setLevel(abs(50 - (parsed_args.VERBOSE * 10)))

	# Call server
	try:
		response, server = discover(magic=parsed_args.MAGIC,
		                            port=parsed_args.PORT,
		                            password=parsed_args.PASSWORD,
		                            timeout=parsed_args.TIMEOUT)

		log.info("Discovered server: '%s - Response: \"%s\"" % (server, str(response)))
	except Exception as e:
		log.info(e)

if __name__ == '__main__':
	main()
