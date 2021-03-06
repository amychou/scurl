#!/usr/bin/env python2.7

import sys
import argparse
import math
import time
from datetime import datetime, timedelta, tzinfo
from OpenSSL import SSL
from OpenSSL import crypto
from urlparse import urlparse
from socket import socket
from dateutil import parser

methods = {'tlsv1.0': SSL.TLSv1_METHOD, 'tlsv1.1': SSL.TLSv1_1_METHOD, 'tlsv1.2': SSL.TLSv1_2_METHOD, 'sslv3' : SSL.SSLv3_METHOD}
PEM = crypto.FILETYPE_PEM
DEFAULT_HTTPS_PORT = 443

def main():
    parser = argparse.ArgumentParser()
    initArgParser(parser)
    args = parser.parse_args()

    if validateURLs(args.urls):
    	global scurl_args
    	scurl_args = setArguments(args)
    	for url_string in args.urls:
    		try:
    			url = urlparse(url_string)
    		except Exception:
    			sys.exit("invalid URL "+url)
    		
    		conn = makeConnection(url)
    		
    		if verifySANS(conn, url.hostname):
    			request(conn, url)
    			get_webpage(conn)
    		else:
    			sys.exit("invalid certificate received!")

    		conn.shutdown()
    		conn.close()

#parses the arguments to scurl
def initArgParser(parser):
    parser.add_argument('--tlsv1.0', action = 'store_const', const = 'tlsv1.0', dest = 'protocol', default = 'tlsv1.2')
    parser.add_argument('--tlsv1.1', action = 'store_const', const = 'tlsv1.1', dest = 'protocol', default = 'tlsv1.2')
    parser.add_argument('--tlsv1.2', action = 'store_const', const = 'tlsv1.2', dest = 'protocol', default = 'tlsv1.2')
    parser.add_argument('--sslv3', '-3', action = 'store_const', const = 'sslv3', dest = 'protocol', default = 'tlsv1.2')

    parser.add_argument('--ciphers', action = 'store', dest = 'ciphers')
    parser.add_argument('--crlfile', action = 'store', dest = 'crlfile')
    parser.add_argument('--cacert', action = 'store', dest = 'cacert')
    parser.add_argument('--allow-stale-certs', action = 'store', dest = 'exp_days')
    parser.add_argument('--pinnedcertificate', action = 'store', dest = 'pinned_cert')

    parser.add_argument('urls', nargs = '*')

#checks for https scheme in every url
def validateURLs(urls):
	if urls == []:
		sys.exit("no url specified!")

	for url in urls:
		try:
			scheme = urlparse(url).scheme
			if scheme != 'https':
				sys.exit(url+" doesn't use https protocol!")
		except Exception:
			sys.exit("Couldn't resolve host "+url)

	return True

#sets all optional arguments for scurl
def setArguments(args):
	scurl_args = {'context': None, 'stale_days': None, 'pinned_cert': None, 'revoked_serials': None}

	context = SSL.Context(methods[args.protocol])

	if args.ciphers is not None:
		try:
			context.set_cipher_list(args.ciphers)
		except Exception:
			sys.exit('invalid cipher list!')

	if args.crlfile is not None:
		try:
			crl_buffer = open(args.crlfile).read()
			crl_object = crypto.load_crl(PEM, crl_buffer)
			crl_revoked = crl_object.get_revoked()

			scurl_args['revoked_serials'] = [int(cert.get_serial(), 16) for cert in crl_revoked]
		except Exception:
			sys.exit('invalid CRL file!')

	if args.cacert is not None:
		try:
			context.load_verify_locations(args.cacert)
		except Exception:
			sys.exit('invalid CA certificate file!')
	else:
		context.set_default_verify_paths()

	if args.exp_days is not None:
		if args.exp_days < 0:
			sys.exit('number of days must be non-negative!')
		else:
			scurl_args['stale_days'] = args.exp_days

	if args.pinned_cert is not None:
		try:
			cert_buffer = open(args.pinned_cert).read()
			scurl_args['pinned_cert'] = crypto.load_certificate(PEM, cert_buffer)
		except Exception:
			sys.exit('invalid pinned public key certificate!')

	scurl_args['context'] = context

	return scurl_args

#returns connection to the url
def makeConnection(url):
	if url.hostname is None:
		sys.exit("no hostname specified")

	#sets a callback function to verify certificate chain against crl and allowed_stale_days
	scurl_args['context'].set_verify(SSL.VERIFY_PEER or SSL.VERIFY_FAIL_IF_NO_PEER_CERT, callback)
	
	tls_socket = socket()
	tls_conn = SSL.Connection(scurl_args['context'], tls_socket)
	port = DEFAULT_HTTPS_PORT

	if url.port is not None:
		port = url.port

	try:
		tls_conn.connect((url.hostname, port))
	except Exception:
		sys.exit("could not connect to URL requested")
	
	tls_conn.set_tlsext_host_name(url.hostname)
	tls_conn.set_connect_state()

	try:
		tls_conn.do_handshake()
	except Exception:
		sys.exit("could not execute handshake")
	return tls_conn

def callback(conn, cert, errno, depth, result):
	if scurl_args['pinned_cert'] is None:
		if isRevoked(cert):
			return False
		if errno == 10:
			return isNotStaleEnough(cert)
		elif errno != 0:
			return False
		return result
	else:
		if depth == 0:
			return equalsPinnedCert(cert)
		else:
			return True

def isRevoked(cert):
	if scurl_args['revoked_serials'] is not None:
		if cert.get_serial_number() in scurl_args['revoked_serials']:
			return True
	return False

def equalsPinnedCert(cert):
	pinned_hash = scurl_args['pinned_cert'].digest("sha256")
	cert_hash = cert.digest("sha256")
	return (pinned_hash == cert_hash)

def isNotStaleEnough(cert):
	ZERO = timedelta(0)
	class UTC(tzinfo):
		def utcoffset(self, dt):
			return ZERO
		def tzname(self, dt):
			return "UTC"
		def dst(self, dt):
			return ZERO
	utc = UTC()

	if scurl_args['stale_days'] is None:
		return False
	n = scurl_args['stale_days']
	expire_date = parser.parse(cert.get_notAfter())
	time_now = datetime.now(utc)
	stale_time = time_now-expire_date

	return (0 <= stale_time.days <= n)

def regexMatch(host, regex):
	if regex[0] == '*':
		try:
			return regex[1:] == host[host.find('.'):]
		except Exception:
			sys.exit("invalid subject alternative name!")
	return host == regex

def verifySANS(conn, host):
	cert = conn.get_peer_certificate()
	san_list = getAlternativeNames(cert)
	for san in san_list:
		if regexMatch(host, san):
			return True

	commonName = cert.get_subject().commonName
	return regexMatch(host, commonName)

def getAlternativeNames(cert):
	san_list = []
	for i in range(cert.get_extension_count()):
		if cert.get_extension(i).get_short_name() == "subjectAltName":
			san_extension = cert.get_extension(i)
			san_str = san_extension.__str__()
			
			san_list = san_str.split(", ")
			for i in range(len(san_list)):
				parsed_alt_name = san_list[i].split(":")[1]
				san_list[i] = parsed_alt_name
	return san_list

def request(conn, url):
	if url.path is not None:
		request_line = "GET "+url.path+" HTTP/1.0\r\n"
	else:
		request_line = "GET / HTTP/1.0\r\n"

	if url.port is None:
		port = DEFAULT_HTTPS_PORT
	else:
		port = url.port

	host = "Host: "+url.hostname+":"+str(port)+"\r\n"
	user_agent = "User-Agent: cs255/scurl\r\n"
	connection = "Connection: close\r\n"

	message = request_line+host+user_agent+connection+"\r\n"

	try:
		conn.sendall(message)
	except Exception:
		sys.exit("couldn't make HTTP request")


def get_webpage(conn, timeout = 2):
	conn.setblocking(False)
	data = ''
	start_time  = time.time()
	while True:
		if time.time()-start_time > timeout:
			break

		try:
			new_data = conn.recv(1024)
			if new_data:
				start_time = time.time()
				data = data+new_data
			else:
				time.sleep(0.1)
		except:
			pass

	print data[data.find("\r\n\r\n")+4:len(data)-1]

main()