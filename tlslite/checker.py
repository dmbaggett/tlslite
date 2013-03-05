# Authors: 
#   Trevor Perrin
#   Dave Baggett (Arcode Corporation)
#
# See the LICENSE file for legal information regarding use of this file.

"""Class for post-handshake certificate checking."""

from .x509 import X509
from .x509certchain import X509CertChain
from .errors import *


class Checker:
    """This class is passed to a handshake function to check the other
    party's certificate chain.

    If a handshake function completes successfully, but the Checker
    judges the other party's certificate chain to be missing or
    inadequate, a subclass of
    L{tlslite.errors.TLSAuthenticationError} will be raised.

    Currently, the Checker can check an X.509 chain.
    """

    def __init__(self, 
                 x509Fingerprints=None,
                 x509RootCerts=None,
                 x509CommonNames=None,
                 checkResumedSession=False,
                 skipCommonNameCheck=False,
                 callback=None,
                 callbackInfo=None):
        """Create a new Checker instance.

        For any certs to pass, you must pass in one or both of these arguments:
         - x509Fingerprints
         - x509RootCerts

        @type x509Fingerprints: iterable of str
        @param x509Fingerprints: An iterable of hex-encoded X.509 fingerprints
        of trusted certs.

        @type x509RootCerts: list of L{tlslite.X509.X509}
        @param x509RootCerts: A list of trusted root certificates.  The
        other party must present a certificate chain which extends to
        one of these root certificates.

        @type x509CommonNames: str or iterable of str
        @param x509CommonName: One of the end-entity certificate's commonName or
        altSubjectName field(s) must be in this set of strings.  For a web server, 
        this is typically a server name such as 'www.amazon.com'. If an iterable
        is provided, any name in the iterable will be allowed.

        @type checkResumedSession: bool
        @param checkResumedSession: If resumed sessions should be
        checked.  This defaults to False, on the theory that if the
        session was checked once, we don't need to bother
        re-checking it.

        @type skipCommonNameCheck: bool
        @param: If the common name check should be skipped. Normally it is performed,
        and the cert will fail unless the cert's name matches on provided in the
        x509CommonNames iterable.

        @type callback: callable
        @param callback: Callable to be called if validation fails. Will be called with a
        dictionary of information about the failure. The validator must return True (allow the
        cert anyway) or False (fail the cert).

        @type callbackInfo: dict
        @param callback_info: Extra dict of info to pass to the callback function, for
        application-specific purposes.
        """

        self.x509Fingerprints = x509Fingerprints
        self.x509RootCerts = x509RootCerts
        self.x509CommonNames = x509CommonNames if hasattr(x509CommonNames, '__iter__') else { x509CommonNames }
        self.skipCommonNameCheck = skipCommonNameCheck
        self.callback = callback
        self.callbackInfo = callbackInfo
        self.checkResumedSession = checkResumedSession
        self.validation_info = None

    def __call__(self, connection):
        """Check a TLSConnection.

        When a Checker is passed to a handshake function, this will
        be called at the end of the function.

        @type connection: L{tlslite.tlsconnection.TLSConnection}
        @param connection: The TLSConnection to examine.

        @raise tlslite.errors.TLSAuthenticationError: If the other
        party's certificate chain is missing or bad.
        """
        assert connection

        if not self.checkResumedSession and connection.resumed:
            return

        # Get the cert chain to validate, depending on our role
        if connection._client:
            chain = connection.session.serverCertChain
        else:
            chain = connection.session.clientCertChain

        if isinstance(chain, X509CertChain):
            self.validation_info = chain.validate(
                self.x509RootCerts, 
                self.x509Fingerprints, 
                self.x509CommonNames,
                self.skipCommonNameCheck,
                self.callback,
                self.callbackInfo)
            if not self.validation_info.get("success"):
                raise TLSValidationError("X.509 validation failure: %s" % self.validation_info, self.validation_info)
        elif chain:
            raise TLSAuthenticationTypeError()
        else:
            raise TLSNoAuthenticationError()

    def getValidationInfo(self):
        return self.validation_info
