#!/usr/bin/env python
#
# Authors: 
#   Trevor Perrin
#   Dave Baggett (Arcode Corporation)

from __future__ import print_function
import sys
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser("test tlslite client")
    parser.add_argument('-s', '--server', action='store', default="localhost", dest='server', help='remote server to connect to')
    parser.add_argument('-p', '--port', action='store', default=None, dest='port', help='remote port to connect to')
    parser.add_argument('-u', '--url', action='store', default=None, dest='url', help='url to fetch')
    parser.add_argument('-r', '--root-certs', action='store', default="cacert.pem", dest='root_certs_file', help='specify pathname to cacerts.pem file')
    parser.add_argument('-f', '--fingerprint', action='append', default=[], dest='server_fingerprints', help='add an allowed server certificate')
    parser.add_argument('-n', '--no-check-certificate', action='store', default=None, dest='nocheck', help="disable validation of remote server's X.509 certificates")
    parser.add_argument('-c', '--no-check-common-name', action='store', default=False, dest='nocheck_common_name', help="disable validation of remote server's commonName/altSubjectNames")
    parser.add_argument('-P', '--python-path', action='append', default=[], dest='syspath', help='append directory python sys.path')
                 
    args = parser.parse_args()

    if args.syspath:
        sys.path = args.syspath + sys.path

    from tlslite import HTTPTLSConnection, HandshakeSettings
    from tlslite.checker import Checker
    from tlslite.x509 import X509

    if args.port is None:
        args.port = 4443 if args.server == 'localhost' else 443
    if args.url is None:
        args.url = "/index.html" if args.server == 'localhost' else "/"
    if args.nocheck is None:
        args.nocheck = True if args.server == 'localhost' else False

    if args.nocheck is None:
        checker = None
    else:
        # Define a callback function for validation failures
        def cert_validation_callback(info):
            print("cert failed validation: %s" % info)
            #Example of how to force a failing cert to pass:
            #info['success'] = True # pass the cert anyway!
            return info

        # Read the cacert.pem file to get trusted root certs
        cacerts_list = X509.certListFromPEM(args.root_certs_file, data_is_pathname=True)

        # Specify allowed common names.
        common_names = [ args.server ]
        if not args.server.startswith('www.'):
            common_names.append('www.' + args.server)

        # Create a cert validation checker
        checker = Checker(
            x509Fingerprints=set(args.server_fingerprints),
            x509RootCerts=cacerts_list,
            x509CommonNames=common_names,
            skipCommonNameCheck=args.nocheck_common_name,
            callback=cert_validation_callback,
            callbackInfo=None)

    settings = HandshakeSettings()
    settings.useExperimentalTackExtension = True

    h = HTTPTLSConnection(args.server, args.port, checker=checker, settings=settings)    
    h.request("GET", args.url)
    r = h.getresponse()
    print(r.read())
