# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

__version__ = "0.4.4"
from .constants import AlertLevel, AlertDescription, Fault
from .errors import *
from .checker import Checker
from .handshakesettings import HandshakeSettings
from .session import Session
from .sessioncache import SessionCache
from .tlsconnection import TLSConnection
from .x509 import X509
from .x509certchain import X509CertChain

try:
    # I don't want dmb as a dependency -- dmb
    from .verifierdb import VerifierDB
except ImportError:
    pass

try:
    # I don't always want the integration stuff -- dmb
    from .integration.httptlsconnection import HTTPTLSConnection
    from .integration.tlssocketservermixin import TLSSocketServerMixIn
    from .integration.tlsasyncdispatchermixin import TLSAsyncDispatcherMixIn
    from .integration.pop3_tls import POP3_TLS
    from .integration.imap4_tls import IMAP4_TLS
    from .integration.smtp_tls import SMTP_TLS
    from .integration.xmlrpctransport import XMLRPCTransport
    from .integration.xmlrpcserver import TLSXMLRPCRequestHandler, \
                                          TLSXMLRPCServer, \
                                          MultiPathTLSXMLRPCServer
except ImportError:
    pass

from .utils.cryptomath import m2cryptoLoaded, gmpyLoaded, \
                             tlscryptoLoaded, pycryptoLoaded, prngName
from .utils.keyfactory import generateRSAKey, parsePEMKey, \
                             parseAsPublicKey, parsePrivateKey
from .utils.tackwrapper import tackpyLoaded
