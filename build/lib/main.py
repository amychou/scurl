import sys
import argparse
from OpenSSL import SSL

versions = {"tlsv1.0": SSL.TLSv1_METHOD, "sslv3": SSL.SSLv3_METHOD}
# "tlsv1.1": SSL.TLSv1_1_METHOD, "tlsv1.2": SSL.TLSv1_2_METHOD don't work, why??

def main(args=None):
    parser = argparse.ArgumentParser()
    initArgParser(parser)
    args = parser.parse_args()
    context = SSL.Context(versions[args.version])

def initArgParser(parser):
    parser.add_argument("--tlsv1.0", dest = "version", action="store_const",
        const="tlsv1.0", default="tlsv1.2",
        help="Forces scurl to use TLS version 1.0 when connecting to a remote TLS server")
    parser.add_argument("--tlsv1.1", dest = "version", action="store_const",
        const="tlsv1.1", default="tlsv1.2",
        help="Forces scurl to use TLS version 1.1 when connecting to a remote TLS server")
    parser.add_argument("--tlsv1.2", dest = "version", action="store_const",
        const="tlsv1.2", default="tlsv1.2",
        help="Forces scurl to use TLS version 1.2 when connecting to a remote TLS server")
    parser.add_argument("--sslv3", "-3", dest = "version", action="store_const",
        const="sslv3", default="tlsv1.2",
        help="Forces curl to use SSL version 3 when negotiating with a remote SSL server")
