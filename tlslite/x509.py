# Authors: 
#   Trevor Perrin
#   Google - parsing subject field
#   Dave Baggett (Arcode Corporation) - refactor; OIDs; stuff for cert
#     verification; support new parsing backends pyasn1 and cx509
#
# See the LICENSE file for legal information regarding use of this file.

"""Class representing an X.509 certificate."""
from __future__ import print_function

import sys
import re
import hashlib
import unicodedata
import array
from base64 import b64decode

from .errors import *
from .oids import OIDS, OID_short_names
from .utils.pem import dePem
from .utils.keyfactory import _createPublicRSAKey

# Get C implementations of other hash functions from tlscrypto
try:
    #raise ImportError # for testing
    import _MD2
except ImportError:
    _MD2 = None

try:
    #raise ImportError # for testing
    import _MD4
except ImportError:
    _MD4 = None

#
# Map OIDs to hasher factories
#
OID_TO_HASHER_INFO = {
    ############################################################################
    # OIDs typically found in DigestInfo:
    #

    # Supported with C extensions above:
    "{ 1.2.840.113549.2.2 }": ('md2', (lambda: _MD2.new()) if _MD2 else None),
    "{ 1.2.840.113549.2.4 }": ('md4', (lambda: _MD4.new()) if _MD4 else None),

    # Supported natively in Python:
    "{ 1.2.840.113549.2.5 }": ('md5', lambda: hashlib.new('md5')),
    "{ 1.3.14.3.2.26 }": ('sha1', lambda: hashlib.new('sha1')),
    "{ 2.16.840.1.101.3.4.2.1 }": ('sha256', lambda: hashlib.new('sha256')),
    "{ 2.16.840.1.101.3.4.2.2 }": ('sha384', lambda: hashlib.new('sha384')),
    "{ 2.16.840.1.101.3.4.2.3 }": ('sha512', lambda: hashlib.new('sha512')),

    ############################################################################
    # OIDs typically found in TBSCertificate.signature, used in conjuction with
    # RSA encryption:
    #

    # "md2WithRSAEncryption":
    "{ 1.2.840.113549.1.1.2 }":  ('md2', (lambda: _MD2.new()) if _MD2 else None),

    # "md4WithRSAEncryption":
    "{ 1.2.840.113549.1.1.3 }":  ('md4', (lambda: _MD4.new()) if _MD4 else None),

    # "md5WithRSAEncryption":
    "{ 1.2.840.113549.1.1.4 }":  ('md5', lambda: hashlib.new('md5')),

    # "sha1WithRSAEncryption":
    "{ 1.2.840.113549.1.1.5 }":  ('sha1', lambda: hashlib.new('sha1')),

    # "sha256WithRSAEncryption":
    "{ 1.2.840.113549.1.1.11 }": ('sha256', lambda: hashlib.new('sha256')),

    # "sha384WithRSAEncryption":
    "{ 1.2.840.113549.1.1.12 }": ('sha384', lambda: hashlib.new('sha384')),

    # "sha512WithRSAEncryption":
    "{ 1.2.840.113549.1.1.13 }": ('sha512', lambda: hashlib.new('sha512'))
    }


class X509(object):
    """This class represents an X.509 certificate.

    @type der: L{bytearray} of unsigned bytes
    @ivar der: The DER-encoded ASN.1 certificate

    @type pem: boolean
    @ivar pem: Is the certificate data encoded in PEM format?

    @type implementation: str
    @ivar implementation: preferred underlying parser implemenation
    """
    def __init__(self, der=None, pem=True, implementation=None):
        # Use cx509 extension (based on asn1c) if available; it's very fast:
        if implementation is None:
            implementation = "cx509"

        # Select implementation based on caller preference (or what we have)
        if implementation == "cx509":
            try:
                import x509cx509
                self.x509 = x509cx509._X509()
            except ImportError:
                self.x509 = None

        if implementation == "pyasn1" or self.x509 is None:
            try:
                import x509pyasn1
                self.x509 = x509pyasn1._X509()
            except ImportError:
                self.x509 = None

        if implementation == "simple" or self.x509 is None:
            try:
                import x509simple
                self.x509 = x509simple._X509()
            except ImportError:
                self.x509 = None

        if self.x509 is None:
            raise TLSUnsupportedError("fatal: no X.509 parser available")

        # Parse the cert data
        if der:
	    self.parse(der, pem=pem)

        # Haven't attempted verification on this cert yet:
        self.verified = None

    @classmethod
    def certListFromPEM(self, data, data_is_pathname=False):
        """Return a list of certs corresponding to the PEM data provided; e.g., data read from
        cacert.pem"""
        from tlslite.utils.pem import dePemList
        if data_is_pathname:
            with open(data, "rb") as f:
                pem = f.read()
        else:
             pem = data
        certs_der_list = dePemList(pem)
        certs = []
        for der in certs_der_list:
            try:
                certs.append(X509(der=der, pem=False))
            except Exception as e:
                print("failed to parse cert: %s" % e)
        return certs

    #
    # The following three property methods are provided for compatibility with
    # historical attribute names.
    #
    @property
    def bytes(self):
        return self.getDER()

    def writeBytes(self):
        return self.getDER()

    @property
    def publicKey(self):
        return self.getPublicKey()

    def parse(self, s, pem=True):
        """
        Interpret the provided string as an X.509 certificate. If pem is True
        the data is assumed to be in PEM format; otherwise, the data is assumed
        to be in binary ASN.1 BER format.
        """
        converted = dePem(s, name="CERTIFICATE") if pem else bytearray(s)
        if self.x509:
            #
            # save the raw DER-format binary data; we'll need it for
            # fingerprinting
            #
            self.cert_binary = converted
            self.x509.parseBinary(self.cert_binary)
        return self

    def parseBinary(self, b):
        "Parse cert from binary ASN.1 BER data."
        return self.parse(b, pem=False)

    def __str__(self):
        "Return a human-readable string representation of the certificate."
        return repr(self.x509) if self.x509 else "<empty>"

    def getFingerprint(self, hash="sha1"):
        """
        Using the specified hash function, determine the fingerprint of the
        ASN.1 DER data of the certificate. Note that this applies to the entire
        Certificate type, not the tbsCertificate subtype.
        """
        hasher = hashlib.new(hash)
        hasher.update(self.cert_binary)
        return hasher.hexdigest()

    def getDER(self):
        "Return the raw, binary, DER-format data for this cert."
        return self.cert_binary

    def getPublicKey(self):
        info = self.getPublicKeyInfo()
        if info.get('algorithm') == 'rsaEncryption' \
                and 'modulus' in info \
                and 'public_exponent' in info:
            return _createPublicRSAKey(info['modulus'], info['public_exponent'])
        raise TLSUnsupportedError(
            "unsupported public key type (algorithm: %s, issuer: %s)"\
                % (info.get('algorithm'), self.getIssuerAsText()))

    def verify(self, other=None):
        """
        Verify the provided certificate using this certificate's public key. If
        no certificate is provided, this certificate will verify itself.
        """
        cert = other or self
        result = self._verify(cert)
        if cert is self:
            # Memoize the result so we don't have to attempt verification again.
            self.verified = result
        return result

    def getDigestInfo(self, key):
        """
        Get the signature value field and decrypt and parse it to produce the
        digest info for this certificate. Memoized.

        The DigestInfo stores a hash ("digest") of the raw ASN.1 bytes for the
        TBSCertificate. The hash function used is specified in the
        DigestInfo. This lets us check whether the TBSCertificate data has been
        tampered with since it was encoded by the CA.
        """
        #
        # Get the signature algorithm (e.g., 'sha1WithRSAEncryption') and make
        # sure the encryption type is one we support (currently only RSA).
        #
        algorithm = self.getSignatureAlgorithm()
        if not algorithm.lower().endswith("withrsaencryption"):
            raise TLSUnsupportedError(
                "TBSCertificate has unsupported signature algorithm %s"\
                    % algorithm)

        #
        # Get the signatureValue; it is an encrypted ASN.1 BER DigestInfo
        # structure.
        #
        signature = bytearray(self.getSignatureValue())

        #
        # Decrypt signatureValue to get the DigestInfo using the RSA public
        # exponent.
        #
        data = key.decryptUsingPublicExponent(signature)
        if data is None:
            raise TLSUnsupportedError(
                "decrypted signatureValue data is in an unsupported format")
            return False

        # Parse the decrypted DigestInfo ASN.1 data
        D = self.x509.parseDigestInfo(data)
        if D:
            D['key'] = key
        return D

    def _verify(self, cert):
        """
        Verify a certificate using this certificate's public key. If other is
        None, this certificate will verify itself.
        """
        try:
            #
            # If we've already tried to verify this cert, just return the
            # previous value. This saves time at start up, so we don't have to
            # verify all the certs in the cacerts.pem file even though we only
            # use a handful of the certs in that file; CA certs are now verified
            # upon first use in x509certchain.py.
            #
            if cert is self:
                if self.verified is not None:
                    return self.verified

            try:
                key = self.getPublicKey()
            except Exception as e:
                print(e)
                return False

            digest_info = cert.getDigestInfo(key)
            digest = digest_info['digest']
            digest_algorithm = digest_info.get('algorithm_oid')
            digest_hash_info = OID_TO_HASHER_INFO.get(digest_algorithm)
            if not digest_hash_info:
                print("unsupported DigestInfo algorithm %s"\
                      % digest_algorithm)
                return False
            
            #
            # Make sure the digest algorithm matches the TBSCertificate
            # algorithm; otherwise, the hashes are incomparable. Although RFC
            # 5280 says the two fields must match, they rarely do in the OID
            # sense; instead, we can only verify that the related hash function
            # matches ("sha-1" vs "sha1WithRSAEncryption").
            #
            TBSCertificate_hash_info = OID_TO_HASHER_INFO.get(
                cert.getSignatureAlgorithm(as_oid=True))
            if not TBSCertificate_hash_info:
                print("unsupported DigestInfo algorithm %s"\
                          % TBSCertificate_hash_info)
                return False
            if digest_hash_info[0] != TBSCertificate_hash_info[0]:
                print("TBSCertificate signature hash algorithm (%s) "
                      "does not match DigestInfo hash algorithm (%s)"\
                          % (digest_hash_info[0], 
                             TBSCertificate_hash_info[0]))
                return False
            
            #
            # If the digest algorithm paramters isn't set to NULL (ASN.1
            # built-in tag 5), fail, since we don't know how to handle
            # parameters.
            #
            #if digest_algorithm_parameters[0] != chr(5):
            #    print("can't handle non-NULL digest algorithm parameter")
            #    return False

            #
            # Look up the digest (hash) algorithm OID to see if our
            # implementation supports it.
            #
            if digest_hash_info is None:
                print("unknown digest algorithm with OID: %s"\
                          % digest_algorithm)
                return False
                      
            #
            # Get the human-readable name of the hash function, and a function
            # to make a hasher using the function.
            #
            (hash_name, hasher_factory) = digest_hash_info
            if hasher_factory is None:
                print("unsupported digest algorithm: %s" % hash_name)
                return False

            #
            # Check the digest in the signature against the actual
            # tbsCertificate digest; they must match. If not, the certificate
            # has been tampered with.
            #
            return cert.tbsDigest(hasher_factory) == digest
        except Exception as e:
            print("WARNING: caught exception verifying cert (%s); "
                  "failing the cert even though it might be good" % e)
            return False
                      
    def tbsDigest(self, hasher_factory):
        data = self.getTBSCertificateData()
        hasher = hasher_factory()
        hasher.update(data)
        return hasher.digest()

    #
    # Methods passed through to the underlying parser implementation
    #
    def extensions(self):
        """
        Return a list of dicts for extensions this certificate
        supports/requires. The keys will depend on the extension type, but the
        critical key will always be set to a boolean value; if critical is True,
        the extension MUST be interpreted, or the certificate cannot be safely
        used.
        """
        return self.x509.extensions()

    def getCriticalExtensions(self):
       return [
           extension 
           for extension in self.extensions() 
           if extension.get('critical')
           ]

    def getExtension(self, name):
        matches = [
            extension
            for extension in self.extensions() 
            if extension.get('name') == name
            ]
        if len(matches) == 1:
            return matches[0]
        return None

    def getVersion(self):
        "Get the certificate version as an integer (0=v1, 1=v2, 2=v3)."
        return self.x509.getVersion()

    def getNotBefore(self):
        "Get the earliest valid date/time in GMT seconds since the epoch."
        return self.x509.getNotBefore()

    def getNotAfter(self):
        "Get the latest valid date/time in GMT seconds since the epoch."
	return self.x509.getNotAfter()

    def getIssuer(self):
        "Returns a dict with information about the certificate issuer."
        return self.x509.getIssuer()

    def getIssuerAsText(self):
        "Returns a string with information about the certificate issuer."
        issuer = self.x509.getIssuer()
        if issuer:
            return self.nameAsText(issuer)
        return None

    def getSubject(self):
        "Returns a dict with information about the certificate subject."
        return self.x509.getSubject()

    def getSubjectAsText(self):
        "Returns a string with information about the certificate subject."
        subject = self.x509.getSubject()
        if subject:
            return self.nameAsText(subject)
        return None

    def getSubjectCommonNames(self):
        """Returns subject commonNames as a list of ASCII strings. This includes
        the commonName component of the subject name as well as any commonName
        components found in subjectAltName extensions.

        The first entry in the list will be the commonName component of the
        subject, if one is provided.

        Note that commonNames may have wildcards (asterisks), and may be
        internationalized domain names (IDNs). For cert chain validation
        purposes, one can ignore the ASCII compaitble encoding (ACE, or
        "punycode") rules, and simply compare the IDNs as case-insignificant
        ASCII strings; the burden is on the certificate creator to convert the
        IDN to plan ASCII using ACE. See RFC 5280, sections 7.2 and 7.3 for
        details."""

        names = []
        N = set() # for uniqifying
        
        def append(names, N, name):
            try:
                n = name.encode("ascii")
                if n not in N:
                    N.add(n)
                    names.append(n)
            except:
                pass # ignore names that won't convert to plain ASCII
                      
        subject = self.x509.getSubject()
        if 'commonName' in subject:
            append(
                names, 
                N, 
                self.ASN1str2unicode(
                    subject['commonName'], 
                    subject.get('commonName:encoding')))
        for name in (
            self.getExtension('subjectAltName') or {})\
            .get('dNSName', []):
            append(names, N, name)
        del subject
        del N
        return names

    def getSignatureAlgorithm(self, as_oid=False):
        "Return the name of the algorithm the CA used to sign this certificate."
        return self.x509.getSignatureAlgorithm(as_oid=as_oid)

    def getSignatureValue(self):
        "Return the raw, encrypted, signature data."
        return self.x509.getSignatureValue()

    def getPublicKeyInfo(self):
        return self.x509.getPublicKeyInfo()

    def getTBSCertificateData(self):
        return self.x509.getTBSCertificateData()

    RE_PROHIBITED = re.compile(u'''[\u0221\u0234-\u024F\u02AE-\u02AF\u02EF-\u02FF\u0350-\u035F\u0370-\u0373\u0376-\u0379\u037B-\u037D\u037F-\u0383\u038B\u038D\u03A2\u03CF\u03F7-\u03FF\u0487\u04CF\u04F6-\u04F7\u04FA-\u04FF\u0510-\u0530\u0557-\u0558\u0560\u0588\u058B-\u0590\u05A2\u05BA\u05C5-\u05CF\u05EB-\u05EF\u05F5-\u060B\u060D-\u061A\u061C-\u061E\u0620\u063B-\u063F\u0656-\u065F\u06EE-\u06EF\u06FF\u070E\u072D-\u072F\u074B-\u077F\u07B2-\u0900\u0904\u093A-\u093B\u094E-\u094F\u0955-\u0957\u0971-\u0980\u0984\u098D-\u098E\u0991-\u0992\u09A9\u09B1\u09B3-\u09B5\u09BA-\u09BB\u09BD\u09C5-\u09C6\u09C9-\u09CA\u09CE-\u09D6\u09D8-\u09DB\u09DE\u09E4-\u09E5\u09FB-\u0A01\u0A03-\u0A04\u0A0B-\u0A0E\u0A11-\u0A12\u0A29\u0A31\u0A34\u0A37\u0A3A-\u0A3B\u0A3D\u0A43-\u0A46\u0A49-\u0A4A\u0A4E-\u0A58\u0A5D\u0A5F-\u0A65\u0A75-\u0A80\u0A84\u0A8C\u0A8E\u0A92\u0AA9\u0AB1\u0AB4\u0ABA-\u0ABB\u0AC6\u0ACA\u0ACE-\u0ACF\u0AD1-\u0ADF\u0AE1-\u0AE5\u0AF0-\u0B00\u0B04\u0B0D-\u0B0E\u0B11-\u0B12\u0B29\u0B31\u0B34-\u0B35\u0B3A-\u0B3B\u0B44-\u0B46\u0B49-\u0B4A\u0B4E-\u0B55\u0B58-\u0B5B\u0B5E\u0B62-\u0B65\u0B71-\u0B81\u0B84\u0B8B-\u0B8D\u0B91\u0B96-\u0B98\u0B9B\u0B9D\u0BA0-\u0BA2\u0BA5-\u0BA7\u0BAB-\u0BAD\u0BB6\u0BBA-\u0BBD\u0BC3-\u0BC5\u0BC9\u0BCE-\u0BD6\u0BD8-\u0BE6\u0BF3-\u0C00\u0C04\u0C0D\u0C11\u0C29\u0C34\u0C3A-\u0C3D\u0C45\u0C49\u0C4E-\u0C54\u0C57-\u0C5F\u0C62-\u0C65\u0C70-\u0C81\u0C84\u0C8D\u0C91\u0CA9\u0CB4\u0CBA-\u0CBD\u0CC5\u0CC9\u0CCE-\u0CD4\u0CD7-\u0CDD\u0CDF\u0CE2-\u0CE5\u0CF0-\u0D01\u0D04\u0D0D\u0D11\u0D29\u0D3A-\u0D3D\u0D44-\u0D45\u0D49\u0D4E-\u0D56\u0D58-\u0D5F\u0D62-\u0D65\u0D70-\u0D81\u0D84\u0D97-\u0D99\u0DB2\u0DBC\u0DBE-\u0DBF\u0DC7-\u0DC9\u0DCB-\u0DCE\u0DD5\u0DD7\u0DE0-\u0DF1\u0DF5-\u0E00\u0E3B-\u0E3E\u0E5C-\u0E80\u0E83\u0E85-\u0E86\u0E89\u0E8B-\u0E8C\u0E8E-\u0E93\u0E98\u0EA0\u0EA4\u0EA6\u0EA8-\u0EA9\u0EAC\u0EBA\u0EBE-\u0EBF\u0EC5\u0EC7\u0ECE-\u0ECF\u0EDA-\u0EDB\u0EDE-\u0EFF\u0F48\u0F6B-\u0F70\u0F8C-\u0F8F\u0F98\u0FBD\u0FCD-\u0FCE\u0FD0-\u0FFF\u1022\u1028\u102B\u1033-\u1035\u103A-\u103F\u105A-\u109F\u10C6-\u10CF\u10F9-\u10FA\u10FC-\u10FF\u115A-\u115E\u11A3-\u11A7\u11FA-\u11FF\u1207\u1247\u1249\u124E-\u124F\u1257\u1259\u125E-\u125F\u1287\u1289\u128E-\u128F\u12AF\u12B1\u12B6-\u12B7\u12BF\u12C1\u12C6-\u12C7\u12CF\u12D7\u12EF\u130F\u1311\u1316-\u1317\u131F\u1347\u135B-\u1360\u137D-\u139F\u13F5-\u1400\u1677-\u167F\u169D-\u169F\u16F1-\u16FF\u170D\u1715-\u171F\u1737-\u173F\u1754-\u175F\u176D\u1771\u1774-\u177F\u17DD-\u17DF\u17EA-\u17FF\u180F\u181A-\u181F\u1878-\u187F\u18AA-\u1DFF\u1E9C-\u1E9F\u1EFA-\u1EFF\u1F16-\u1F17\u1F1E-\u1F1F\u1F46-\u1F47\u1F4E-\u1F4F\u1F58\u1F5A\u1F5C\u1F5E\u1F7E-\u1F7F\u1FB5\u1FC5\u1FD4-\u1FD5\u1FDC\u1FF0-\u1FF1\u1FF5\u1FFF\u2053-\u2056\u2058-\u205E\u2064-\u2069\u2072-\u2073\u208F-\u209F\u20B2-\u20CF\u20EB-\u20FF\u213B-\u213C\u214C-\u2152\u2184-\u218F\u23CF-\u23FF\u2427-\u243F\u244B-\u245F\u24FF\u2614-\u2615\u2618\u267E-\u267F\u268A-\u2700\u2705\u270A-\u270B\u2728\u274C\u274E\u2753-\u2755\u2757\u275F-\u2760\u2795-\u2797\u27B0\u27BF-\u27CF\u27EC-\u27EF\u2B00-\u2E7F\u2E9A\u2EF4-\u2EFF\u2FD6-\u2FEF\u2FFC-\u2FFF\u3040\u3097-\u3098\u3100-\u3104\u312D-\u3130\u318F\u31B8-\u31EF\u321D-\u321F\u3244-\u3250\u327C-\u327E\u32CC-\u32CF\u32FF\u3377-\u337A\u33DE-\u33DF\u33FF\u4DB6-\u4DFF\u9FA6-\u9FFF\uA48D-\uA48F\uA4C7-\uABFF\uD7A4-\uD7FF\uFA2E-\uFA2F\uFA6B-\uFAFF\uFB07-\uFB12\uFB18-\uFB1C\uFB37\uFB3D\uFB3F\uFB42\uFB45\uFBB2-\uFBD2\uFD40-\uFD4F\uFD90-\uFD91\uFDC8-\uFDCF\uFDFD-\uFDFF\uFE10-\uFE1F\uFE24-\uFE2F\uFE47-\uFE48\uFE53\uFE67\uFE6C-\uFE6F\uFE75\uFEFD-\uFEFE\uFF00\uFFBF-\uFFC1\uFFC8-\uFFC9\uFFD0-\uFFD1\uFFD8-\uFFD9\uFFDD-\uFFDF\uFFE7\uFFEF-\uFFF8\u0340\u0341\u200E\u200F\u202A\u202B\u202C\u202D\u202E\u206A\u206B\u206C\u206D\u206E\u206F\uE000-\uF8FF\uFDD0-\uFDEF\uFFFE-\uFFFF\uD800-\uDFFF\uFFFD]''', re.UNICODE)
    RE_BIDI = re.compile(u'''[\u200E\u200F\u202A\u202B\u202C\u202D\u202E]''', re.UNICODE)
    RE_MAP_TO_NOTHING = re.compile(u'''[\u0000-\u0008\u000E-\u001F\u007F-\u0084\u0086-\u009F\u00ad\u034F\u06DD\u070F\u1806\u180B-\u180D\u180E\u200B\u200C-\u200F\u202A-\u202E\u2060-\u2063\u206A-\u206F\uFEFF\uFF00-\uFF0F\uFFF9-\uFFFB\uFFFC]''', re.UNICODE)
    RE_MAP_TO_SPACE = re.compile(u'''[\u0009\u000A\u000B\u000C\u000D\u0020\u0085\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]''', re.UNICODE)
    RE_WHITESPACE_SEQ = re.compile('\s+', re.UNICODE)

    @classmethod
    def ASN1str2unicode(C, n, encoding):
        "Convert a ASN.1 name string to Unicode."
        if encoding in ('utf8', 'x500-universal', 'x500-bmp', 'x500-teletex'):
            try:
                # Assume UTF-8
                n = n.decode("utf8")
            except:
                # Assume UTF-8, but ignore bad chars
                try:
                    n = n.decode("utf8", "ignore")
                except:
                    raise ValueError("could not convert value to Unicode")
        else:
            try:
                # Assume plain ASCII
                n = n.decode("ascii")
            except:
                try:
                    # Try UTF-8
                    n = n.decode("utf8")
                except:
                    # Try UTF-8, but ignore bad chars
                    try:
                        n = n.decode("utf8", "ignore")
                    except:
                        raise ValueError("could not convert value to Unicode")
        return n

    @classmethod
    def nameEquality(C, n1, n2):
        """
        Compare two dicts describing X.509 Relative Distinguished Names -- e.g.,
        subject and issuer -- and return True if the names match. The full set
        of name comparison rules is defined in RFC 4518.
        """
        #
        # RFC 5280:
        #
        # Conforming implementations MUST use the LDAP StringPrep profile
        # (including insignificant space handling), as specified in [RFC4518],
        # as the basis for comparison of distinguished name attributes encoded
        # in either PrintableString or UTF8String.  Conforming implementations
        # MUST support name comparisons using caseIgnoreMatch.  Support for
        # attribute types that use other equality matching rules is optional.
        #
        # Before comparing names using the caseIgnoreMatch matching rule,
        # conforming implementations MUST perform the six-step string
        # preparation algorithm described in [RFC4518] for each attribute of
        # type DirectoryString, with the following clarifications:
        # 
        # * In step 2, Map, the mapping shall include case folding as specified
        # in Appendix B.2 of [RFC3454].
        #
        # * In step 6, Insignificant Character Removal, perform white space
        # compression as specified in Section 2.6.1, Insignificant Space
        # Handling, of [RFC4518].
        #
        # When performing the string preparation algorithm, attributes MUST be
        # treated as stored values.
        #
        # Comparisons of domainComponent attributes MUST be performed as
        # specified in Section 7.3.
        #
        # Two naming attributes match if the attribute types are the same and
        # the values of the attributes are an exact match after processing with
        # the string preparation algorithm.  Two relative distinguished names
        # RDN1 and RDN2 match if they have the same number of naming attributes
        # and for each naming attribute in RDN1 there is a matching naming
        # attribute in RDN2.  Two distinguished names DN1 and DN2 match if they
        # have the same number of RDNs, for each RDN in DN1 there is a matching
        # RDN in DN2, and the matching RDNs appear in the same order in both
        # DNs.  A distinguished name DN1 is within the subtree defined by the
        # distinguished name DN2 if DN1 contains at least as many RDNs as DN2,
        # and DN1 and DN2 are a match when trailing RDNs in DN1 are ignored.
        #
        # TBD: this still isn't done; see the insanity in section 7.1 of RFC
        # 5280 regarding internationalized domain names.
        #
        N = [n1, n2]
        keys = [set(n1.keys()), set(n2.keys())]

        # Make sure each component found in one exists in the other.
        if keys[0] != keys[1]:
            return False

        # 2.1 Transcode (to Unicode)
        for component in keys[1]:
            if component.endswith(":encoding"):
                continue
            if component.endswith(":oid"):
                continue

            V = [None, None]
            for i in (0, 1):
                encoding = N[i].get(component + ":encoding")
                if encoding is None:
                    return False

                try:
                    V[i] = C.ASN1str2unicode(N[i].get(component), encoding)
                except:
                    return False

                # 2.2 Map
                V[i] = C.RE_MAP_TO_SPACE.sub(' ', V[i])
                V[i] = C.RE_MAP_TO_NOTHING.sub('', V[i])
                V[i] = V[i].lower()

                # 2.3 Normalize
                V[i] = unicodedata.normalize("NFKC", V[i])

                # 2.4 Prohibit
                if C.RE_PROHIBITED.search(V[i]) is not None:
                    return False

                # 2.5 Bidi
                V[i] = C.RE_BIDI.sub('', V[i])

                # 2.6.1 Insignificant Space Handling
                V[i] = C.RE_WHITESPACE_SEQ.sub(' ', V[i])

                #
                # For now, I'm going to pretend these don't exist, because
                # they're insane. -- dmb
                #
                # 2.6.  Insignificant Character Handling
                # 2.6.2 numericString Insignificant Character Handling
                # 2.6.3 telephoneNumber Insignificant Character Handling
                #

            if V[0] != V[1]:
                return False

        # All components matched; the names are equal:
        return True

    def nameAsText(C, n):
        """
        Convert an ASN.1 Relative Distinguished Name to a single-line Unicode
        string, (somewhat) according to RFC 4514.
        """
        # Get RDN components
        components = [
            (k[0:-4], v)
            for k, v in n.items()
            if k.endswith(':oid')
            ]

        # Sort into canonical order
        components.sort(C.compare_oid_tuples)

        #
        # Replace keys with abbreviations where possible; look up values and
        # convert to Unicode.
        #
        return u','.join([
                "%s=%s" % (
                    OID_short_names.get(v, k),
                    C.escape_dn_chars(
                        C.ASN1str2unicode(
                            n[k], 
                            encoding=n.get(k + ":encoding")))
                    )
                for k, v in components
                if k in n # safety: guard against OID with no corresponding key
                ])

    @staticmethod
    def compare_oid_tuples(t1, t2):
        "Return -1, 0, or 1 based on whether o1<o2, o1==o2, or o1>o2."
        try:
            o1 = t1[1]
        except:
            o1 = ""
        try:
            o2 = t2[1]
        except:
            o1 = ""

        a1, a2 = None, None

        if len(o1) > 4:
            if o1[0] == '{' and o1[-1] == '}': # oid string?
                try:
                    a1 = [int(x) for x in o1[1:-1].split('.')]
                except:
                    pass

        if len(o2) > 4:
            if o2[0] == '{' and o2[-1] == '}': # oid string?
                try:
                    a2 = [int(x) for x in o2[1:-1].split('.')]
                except:
                    pass

        if a1 is None and a2 != None:
            return 1
        if a1 is not None and a2 is None:
            return -1

        if a1 is None and a2 is None:
            #
            # Neither oid is a proper dotted string; just compare
            # lexicographically.
            #
            if o1 < o2:
                return -1
            if o1 > o2:
                return 1
            return 0
        
        # Both oids are proper dotted string; compare arc values numerically
        if a1 < a2:
            return 1
        if a1 > a2:
            return -1
        return 0

    #
    # This is taken from python-ldap-2.3.11, used here under a Python License.
    #
    @staticmethod
    def escape_dn_chars(s):
        """Escape all DN special characters found in s with a back-slash (see
        RFC 4514, section 2.4)"""
        if s:
            s = s.replace('\\','\\\\')
        s = s.replace(',' ,'\\,')
        s = s.replace('+' ,'\\+')
        s = s.replace('"' ,'\\"')
        s = s.replace('<' ,'\\<')
        s = s.replace('>' ,'\\>')
        s = s.replace(';' ,'\\;')
        s = s.replace('=' ,'\\=')
        s = s.replace('\000' ,'\\\000')    
        if s[0] == '#' or s[0] == ' ':
            s = ''.join(('\\',s))
        if s[-1] == ' ':
            s = ''.join((s[:-1],'\\ '))
        return s
