import sys
import argparse
import math
from OpenSSL import SSL
from OpenSSL import crypto
from urlparse import urlparse

methods = {'tlsv1.0': SSL.TLSv1_METHOD, 'tlsv1.1': SSL.TLSv1_1_METHOD, 'tlsv1.2': SSL.TLSv1_2_METHOD, 'sslv3' : SSL.SSLv3_METHOD}
pem = crypto.FILETYPE_PEM

def main(args = None):
    parser = argparse.ArgumentParser()
    initArgParser(parser)
    args = parser.parse_args()

    if validateURLs(args.urls):
    	scurl_args = setArguments(args)


def initArgParser(parser):
    parser.add_argument('--tlsv1.0', action = 'store_const', const = 'tlsv1.0', dest = 'protocol', default = 'tlsv1.2')
    parser.add_argument('--tlsv1.1', action = 'store_const', const = 'tlsv1.1', dest = 'protocol', default = 'tlsv1.2')
    parser.add_argument('--tlsv1.2', action = 'store_const', const = 'tlsv1.2', dest = 'protocol', default = 'tlsv1.2')
    parser.add_argument('--sslv3', '-3', action = 'store_const', const = 'sslv3', dest = 'protocol', default = 'tlsv1.2')

    parser.add_argument('--ciphers', action = 'store', dest = 'ciphers')
    parser.add_argument('--crlfile', action = 'store', dest = 'crlfile')
    parser.add_argument('--cacert', action = 'store', dest = 'cacert')
    parser.add_argument('--allow-stale-certs', action = 'store', dest = 'exp_days', type = int)
    parser.add_argument('--pinnedcertificate', action = 'store', dest = 'pinned_cert')

    parser.add_argument('urls', nargs = '+')	

def validateURLs(urls):
    if urls != []:
    	for url in urls:
    		try:
    			scheme = urlparse(url).scheme
    			if scheme != 'https':
    				sys.exit(url+" doesn't use https protocol!")
    		except Exception:
    			sys.exit("Couldn't resolve host "+url)
    	return True;

def setArguments(args):
	context = SSL.Context(methods[args.protocol])

	if args.ciphers is not None:
		try:
			context.set_cipher_list(args.ciphers)
		except Exception:
			sys.exit('invalid cipher list!')

	if args.crlfile is not None:
		try:
			crl_buffer = args.crlfile.read()
			crl_object = crypto.load_crl(pem, crl_buffer)
			cert_revoked = crl_object.get_revoked()
		except Exception:
			sys.exit('invalid CRL file!')
	else:
		cert_revoked = None

	if args.cacert is not None:
		try:
			context.load_verify_locations(args.cacert)
		except Exception:
			sys.exit('invalid CA certificate file!')
	else:
		context.set_default_verify_paths()

	if args.exp_days is not None:
		if args.exp_days < 0:
			raise argparse.ArgumentTypeError('number of days must be non-negative!')
		else:
			allowed_stale_days = args.exp_days
	else:
		allowed_stale_days = None

	if args.pinned_cert is not None:
		try:
			cert_buffer = args.pinned_cert.read()
			pinned_pkey_cert = crypto.load_certificate(pem, cert_buffer)
		except Exception:
			sys.exit('invalid pinned public key certificate')
	else:
		pinned_pkey_cert = None

	scurl_args = {'context': context, 'revoked': cert_revoked, 'stale_days': allowed_stale_days, 'pinned_cert': pinned_pkey_cert}
	return scurl_args
