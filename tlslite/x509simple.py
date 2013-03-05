# Authors: 
#   Trevor Perrin
#
# See the LICENSE file for legal information regarding use of this file.

"""X.509 cert parsing, implemented using pure python."""
import time
import calendar
import hashlib
import re

from.errors import TLSUnsupportedError
from .utils.asn1parser import ASN1Parser
from .utils.keyfactory import _createPublicRSAKey
from .utils.pem import *
from .utils.cryptomath import *

class _X509(object):
    """This class represents an X.509 certificate.

    @type x509: String
    @ivar x509: Either the original certificate or the converted binary
    """

    def parse(self, s):
        """Parse a PEM-encoded X.509 certificate.

        @type s: str
        @param s: A PEM-encoded X.509 certificate (i.e. a base64-encoded
        certificate wrapped with "-----BEGIN CERTIFICATE-----" and
        "-----END CERTIFICATE-----" tags).
        """

        _bytes = dePem(s, "CERTIFICATE")
        self.parseBinary(_bytes)
        return self

    def parseBinary(self, _bytes):
        """Parse a DER-encoded X.509 certificate.

        @type _bytes: str or L{bytearray} of unsigned _bytes
        @param _bytes: A DER-encoded X.509 certificate.
        """
        self._bytes = bytearray(_bytes)
        p = ASN1Parser(_bytes)

        #Get the tbsCertificate
        tbsCertificateP = p.getChild(0)

        #Is the optional version field present?
        #This determines which index the key is at.
        if tbsCertificateP.value[0]==0xA0:
            subjectPublicKeyInfoIndex = 6
        else:
            subjectPublicKeyInfoIndex = 5

        #Get the subject
        self.subject = tbsCertificateP.getChildBytes(\
                           subjectPublicKeyInfoIndex - 1)

        #Get the subjectPublicKeyInfo
        subjectPublicKeyInfoP = tbsCertificateP.getChild(\
                                    subjectPublicKeyInfoIndex)

        #Get the algorithm
        algorithmP = subjectPublicKeyInfoP.getChild(0)
        rsaOID = algorithmP.value
        if list(rsaOID) != [6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0]:
            raise SyntaxError("Unrecognized AlgorithmIdentifier")

        self.algorithm_oid = "{ 1.2.840.113549.1.1.1 }"
        self.algorithm = "rsaEncryption"

        #Get the subjectPublicKey
        subjectPublicKeyP = subjectPublicKeyInfoP.getChild(1)

        #Adjust for BIT STRING encapsulation
        if (subjectPublicKeyP.value[0] !=0):
            raise SyntaxError()
        subjectPublicKeyP = ASN1Parser(subjectPublicKeyP.value[1:])

        #Get the modulus and exponent
        modulusP = subjectPublicKeyP.getChild(0)
        publicExponentP = subjectPublicKeyP.getChild(1)

        #Decode them into numbers
        self.modulus = bytesToNumber(modulusP.value)
        self.publicExponent = bytesToNumber(publicExponentP.value)

        #Create a public key instance
        self._publicKey = _createPublicRSAKey(self.modulus, self.publicExponent)

    def getDER(self):
        "Return the raw ASN.1 bytes for this certificate."
        return self._bytes

    def getPublicKeyInfo(self):
        "Return information about this certificate's public key."
        return {
            'algorithm_oid': self.algorithm_oid, 
            'algorithm': self.algorithm,
            'modulus': self.modulus,
            'public_exponent': self.publicExponent,
            'key': self._publicKey,
            'keylen': len(self._publicKey)
            }

    def extensions(self):
        raise TLSUnsupportedError("can't get extensions with this implementation")

    def getVersion(self):
        "Return integral version of this certificate."
        raise TLSUnsupportedError("can't get X509 version with this implementation")

    def getNotBefore(self):
        raise TLSUnsupportedError("can't get effective dates with this implementation")

    def getNotAfter(self):
        raise TLSUnsupportedError("can't get effective dates with this implementation")

    def getIssuer(self):
        "Return a dict with information about the certificate issuer."
        raise TLSUnsupportedError("can't get issuer with this implementation")

    def getSubject(self):
        "Return a dict with information about the certificate subject."
        raise TLSUnsupportedError("can't get subject with this implementation")

    def getSignatureAlgorithm(self, as_oid):
        raise TLSUnsupportedError("can't get signature algorithm with this implementation")

    def getSignatureValue(self):
        raise TLSUnsupportedError("can't get signature value with this implementation")

    def getTBSCertificateData(self):
        "Return the raw bytes of the ASN.1 DER tbsCertificate."
        raise TLSUnsupportedError("can't get tbsCertificate component with this implementation")
        return der_encoder.encode(self.cert.getComponentByName('tbsCertificate'))

    def parseDigestInfo(self, data):
        """Get the signature value field and decrypt and parse it to produce the
        digest info for this certificate."""
        raise TLSUnsupportedError("can't parse DigestInfo with this implementation")
