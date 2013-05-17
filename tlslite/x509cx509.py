# Authors: 
#   Dave Baggett (Arcode Corporation)
#
# See the LICENSE file for legal information regarding use of this file.

"""X.509 cert parsing, implemented using cx509 extension."""
import time
import calendar
from cx509 import cx509
from utils.compat import bytesToString

class _X509(cx509):
    def parseBinary(self, binary):
        "Parse the ASN.1 BER data for the cert."
        self._parse(bytes(binary))

    def getVersion(self):
        return self.get_version()

    def _str2time(self, timestring):
        """
        Helper function to convert ASN.1 GeneralizedTime to seconds since the
        epoch UTC. Unlike the version built in to asn1c, this works for time
        values larger than sys.maxint under 32-bit python.
        """
        if not timestring:
            return 0

        #
        # NOTE: the time can be larger than is expressible using a 32-bit
        # Python; e.g., 380731122950Z. In this case, the number of seconds will
        # be correct (2164192190L in this case), but this value won't be
        # convertible to a system time_t value.
        #
        return calendar.timegm(
            time.strptime(
                timestring[0:4]    + ' ' +
                timestring[4:6]    + ' ' +
                timestring[6:8]    + ' ' +
                timestring[8:10]   + ' ' +
                timestring[10:12]  + ' ' +
                timestring[12:14],
                '%Y %m %d %H %M %S'))
        
    def getNotBefore(self):
        return self._str2time(self.get_validity()[0])

    def getNotAfter(self):
        return self._str2time(self.get_validity()[1])

    def getIssuer(self):
        return self.get_issuer()

    def getSubject(self):
        return self.get_subject()

    def getSignatureAlgorithm(self, as_oid):
        return self.get_signature_algorithm(as_oid)

    def getSignatureValue(self):
        return bytes(self.get_signature_value())

    def parseDigestInfo(self, data):
        return self.parse_digest_info(bytesToString(data))

    def getPublicKeyInfo(self):
        return self.get_public_key()

    def getTBSCertificateData(self):
        return bytes(self.get_tbs_certificate_data())
