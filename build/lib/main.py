import sys
import argparse
from OpenSSL import SSL
from OpenSSL import crypto
from urlparse import urlparse

versions = {'tlsv1.0': SSL.TLSv1_METHOD, 'tlsv1.1': SSL.TLSv1_1_METHOD, 'tlsv1.2': SSL.TLSv1_2_METHOD, 'sslv3' : SSL.SSLv3_METHOD}

def main(args=None):
    parser = argparse.ArgumentParser()
    initArgParser(parser)
    args = parser.parse_args()

    validateURLs(args.urls)

    context = SSL.Context(versions[args.version])

def initArgParser(parser):
    parser.add_argument('--tlsv1.0', action = 'store_const', const = 'tlsv1.0', dest = 'version', default = 'tlsv1.2')
    parser.add_argument('--tlsv1.1', action = 'store_const', const = 'tlsv1.1', dest = 'version', default = 'tlsv1.2')
    parser.add_argument('--tlsv1.2', action = 'store_const', const = 'tlsv1.2', dest = 'version', default = 'tlsv1.2')
    parser.add_argument('--sslv3', '-3', action = 'store_const', const = 'sslv3', dest = 'version', default = 'tlsv1.2')

    parser.add_argument('--ciphers', action = 'store', dest = 'ciphers')
    parser.add_argument('--crlfile', action = 'store', dest = 'crlfile')
    parser.add_argument('--cacert', action = 'store', dest = 'cacert')
    parser.add_argument('--allow-stale-certs', action = 'store', dest = 'exp_days')
    parser.add_argument('--pinnedcertificate', action = 'store', dest = 'cert_file')

    parser.add_argument('urls', nargs = '*')

def validateURLs(urls):
    if urls != []:
    	for url in urls:
    		scheme = urlparse(url).scheme
    		if scheme != 'https':
    			sys.exit("URL doesn't use https protocol")
    			