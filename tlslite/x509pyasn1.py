# Authors: 
#   Dave Baggett (Arcode Corporation)
#
# See the LICENSE file for legal information regarding use of this file.

"""X.509 cert parsing, implemented using pyasn1."""
import time
import calendar
import hashlib
import re

#
# Note: you can find pyasn1 on PyPI:
#
#   https://pypi.python.org/pypi/pyasn1
#
# This code has been tested with version 0.16.
#
import pyasn1.type.univ
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1 import error

# Try to get bit pattern -> byte accelerator table
try:
    from pyasn1.codec.bitpattern import BITPATTERN_TO_BYTE
except ImportError:
    # Tuples corresponding to bit patterns from 0 to 255:
    BITPATTERN = [
        tuple(((x >> shift)  & 1)
              for shift in reversed(range(8)))
        for x in range(256)
    ]

    # dict mapping bit patterns to characters
    BITPATTERN_TO_BYTE = dict(
        (pattern, chr(value))
        for value, pattern in enumerate(BITPATTERN)
    )

# Get OIDs relevant to X.509 certificate parsing and validation
from oids import OIDS, OID_short_names

def oid2str(oid):
    "Convert a on OID tuple to an OID string."
    return "{ %s }" % ".".join([str(arc) for arc in oid])

#
# ASN.1 data structures for X509.
#
# See RFC 5280 for (a lot) more details.
#

# I have no idea what the right maximum should be here. --dmb
MAX = 2048

class DirectoryString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'teletexString', 
            char.TeletexString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),

        namedtype.NamedType(
            'printableString', 
            char.PrintableString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),

        namedtype.NamedType(
            'universalString', 
            char.UniversalString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),

        namedtype.NamedType(
            'utf8String', 
            char.UTF8String().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),

        namedtype.NamedType(
            'bmpString', 
            char.BMPString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),

        namedtype.NamedType(
            'ia5String', 
            char.IA5String().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX)))
        )

class AttributeValue(DirectoryString):
    # NOTE: asterisk isn't allowed by the X.500 spec, but we allow it anyway:
    PRINTABLE_STRING_REPLACE_RE = re.compile(r'''[^A-Za-z0-9'()+,.=/:?Q \t\r\n-]''')
    WHITESPACE_RE = re.compile(r'[ \t\r\n]+')
    def getStringAndEncoding(self):
        """
        From RFC 3280:
       
          This specification requires only a subset of the name comparison
          functionality specified in the X.500 series of specifications.
          Conforming implementations are REQUIRED to implement the following
          name comparison rules:
       
             (a) attribute values encoded in different types (e.g.,
             PrintableString and BMPString) MAY be assumed to represent
             different strings;
       
             (b) attribute values in types other than PrintableString are case
             sensitive (this permits matching of attribute values as binary
             objects);
       
             (c) attribute values in PrintableString are not case sensitive
             (e.g., "Marianne Swanson" is the same as "MARIANNE SWANSON"); and
       
             (d) attribute values in PrintableString are compared after removing
             leading and trailing white space and converting internal substrings
             of one or more consecutive white space characters to a single
             space.
       
          These name comparison rules permit a certificate user to validate
          certificates issued using languages or encodings unfamiliar to the
          certificate user.
       
        What this means for us:
       
        - we need to return both the string contents and the encoding for each string
        - we need to normalize PrintableString values as noted above
        """
        for string_type in [
            # preferrred:
            'printableString', 'utf8String', 'ia5String', 
            # obsolete:
            'teletexString', 'universalString', 'bmpString', 
            # sentinel:
            None]:
            if string_type is None:
                return ("", "x500-unknown")
            if self.getComponentByName(string_type) is not None:
                break
        if string_type == 'printableString':
            #
            # NOTE: I don't convert case in the string, but that's essential to
            # do when comparing for name equality! --dmb
            #
            return (
                self.WHITESPACE_RE.sub(
                    ' ', 
                    self.PRINTABLE_STRING_REPLACE_RE.sub(
                        '*', str(self.getComponentByName(string_type)).strip())),
                "ascii")
        elif string_type == 'utf8String':
            # Note: the upstream class handles RFC4518 "string prep" for us
            return (str(self.getComponentByName(string_type)), "utf8")
        elif string_type == 'ia5String':
            return (str(self.getComponentByName(string_type)), "ia5")
        elif string_type == 'teletexString':
            return (str(self.getComponentByName(string_type)), "x500-teletex")
        elif string_type == 'universalString':
            return (str(self.getComponentByName(string_type)), "x500-universal")
        elif string_type == 'bmpString':
            return (str(self.getComponentByName(string_type)), "x500-bmp")

class AttributeType(univ.ObjectIdentifier): 
    pass

class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('value', AttributeValue())
        )

class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()

class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()

class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('', RDNSequence())
        )

class AlgorithmIdentifier(univ.Sequence):
    #
    # The algorithm parameter is generally supposed to be NULL, but rather than
    # specify univ.Null here, we just allow Any and then explicitly check for
    # Null values when we need to, so a malformed cert will still parse.
    #
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any())
        )

class Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', univ.Boolean('False')),
        namedtype.NamedType('extnValue', univ.OctetString())
        )

    def extnID(self):
        return self.getComponentByName('extnID')

    def isCritical(self):
        if self.getComponentByName('critical') == False:
	    return False
	else:
	    return True
        
    def extnValue(self):
        return self.getComponentByName('extnValue')

    def extnName(self):
	ID = self.extnID()
	if ID in OIDS:
	    return OIDS[ID]
	else:
	    return None

class Extensions(univ.SequenceOf):
    componentType = Extension()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)

class SubjectPublicKeyInfo(univ.Sequence):
     componentType = namedtype.NamedTypes(
         namedtype.NamedType('algorithm', AlgorithmIdentifier()),
         namedtype.NamedType('subjectPublicKey', univ.BitString())
         )

class UniqueIdentifier(univ.BitString):
    pass

class Time(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('utcTime', useful.UTCTime()),
        namedtype.NamedType('generalTime', useful.GeneralizedTime())
        )
    
class Validity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('notBefore', Time()),
        namedtype.NamedType('notAfter', Time())
        )

class CertificateSerialNumber(univ.Integer):
    pass

class Version(univ.Integer):
    namedValues = namedval.NamedValues(
        ('v1', 0), ('v2', 1), ('v3', 2)
        )

class TBSCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType(
            'version', 
            Version('v1', 
                    tagSet=Version.tagSet.tagExplicitly(
                    tag.Tag(tag.tagClassContext, 
                            tag.tagFormatSimple, 
                            0)))),
        namedtype.NamedType('serialNumber', CertificateSerialNumber()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('issuer', Name()),
        namedtype.NamedType('validity', Validity()),
        namedtype.NamedType('subject', Name()),
        namedtype.NamedType(
            'subjectPublicKeyInfo', 
            SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType(
            'issuerUniqueID', 
            UniqueIdentifier().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, 
                    tag.tagFormatSimple, 
                    1))),
        namedtype.OptionalNamedType(
            'subjectUniqueID', 
            UniqueIdentifier().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, 
                    tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType(
            'extensions', 
            Extensions().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatSimple, 
                    3)))
        )

class Certificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertificate', TBSCertificate()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', univ.BitString())
        )

class BasicConstraints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('cA', univ.Boolean('False')),
    	namedtype.OptionalNamedType('pathLenConstraint', univ.Integer())
        )

    def isCA(self):
        return self.getComponentByPosition(0)

    def getPathLenConstraint(self):
	if (len(self) == 2):
	    return self.getComponentByPosition(1)
	else:
	    return None

class KeyUsage(univ.BitString):
    FLAGS = {
        'digitalSignature': 0,
        'nonRepudiation': 1,
        'keyEncipherment': 2,
        'dataEncipherment': 3,
        'keyAgreement': 4,
        'keyCertSign': 5,
        'cRLSign': 6,
        'encipherOnly': 7,
        'decipherOnly': 8
        }

    def has(self, flag):
        bit = self.FLAGS.get(flag)
        if bit is None:
            return False
        try:
            return bool(self[bit])
        except IndexError:
            return False

class GeneralName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'otherName', 
            univ.Sequence().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, 
                    tag.tagFormatConstructed, 
                    0x0))),

        namedtype.NamedType(
            'rfc822Name', 
            char.IA5String().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, 
                    tag.tagFormatConstructed, 
                    0x1))),

        namedtype.NamedType(
            'dNSName', 
            char.IA5String().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, 
                    tag.tagFormatConstructed, 
                    0x2))),

        namedtype.NamedType(
            'x400Address', 
            univ.Sequence().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, 
                    tag.tagFormatConstructed, 
                    0x3))),

        namedtype.NamedType(
            'directoryName', 
            Name().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, 
                    tag.tagFormatConstructed, 
                    0x4))),

        namedtype.NamedType(
            'ediPartyName', 
            univ.Sequence().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, 
                    tag.tagFormatConstructed, 
                    0x5))),

        namedtype.NamedType(
            'uniformResourceIdentifier', 
            char.IA5String().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, 
                    tag.tagFormatConstructed, 
                    0x6))),

        namedtype.NamedType(
            'iPAddress', 
            univ.OctetString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, 
                    tag.tagFormatConstructed, 
                    0x7))),

        namedtype.NamedType(
            'registeredID', 
            univ.ObjectIdentifier().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, 
                    tag.tagFormatConstructed, 
                    0x8))),
        )

class GeneralNames(univ.SequenceOf):
    componentType = GeneralName()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)

class SubjectAltName(GeneralNames):
    pass

class RSAPublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
	namedtype.NamedType('modulus', univ.Integer()),
	namedtype.NamedType('publicExponent', univ.Integer())
	)

class DigestAlgorithmIdentifier(AlgorithmIdentifier):
  pass

class Digest(univ.OctetString):
  pass

class DigestInfo(univ.Sequence):
  componentType = namedtype.NamedTypes(
      namedtype.NamedType('digestAlgorithm', DigestAlgorithmIdentifier()),
      namedtype.NamedType('digest', Digest()))

# end of ASN.1 data structures

class _X509(object):
    """This class represents an X.509 certificate.

    @type x509: String
    @ivar x509: Either the original certificate or the converted binary
    """
    def __getstate__(self):
        "Replace unpickleable attributes with None."
        state = {}
        state.update(self.__dict__)
        state['digest_info'] = None
        return state

    def parseBinary(self, binary):
        "Parse the ASN.1 BER data for the cert."
	self.cert = der_decoder.decode(bytes(binary), asn1Spec=Certificate())[0]

    def extensions(self):
        E = []
        if self.cert.getComponentByName('tbsCertificate')\
                .getComponentByName('extensions') is not None:
            for i in range(0, 
                           len(self.cert\
                                   .getComponentByName('tbsCertificate')\
                                   .getComponentByName('extensions'))):
                ext = self.cert.getComponentByName('tbsCertificate')\
                    .getComponentByName('extensions')\
                    .getComponentByPosition(i)
                oidstr = oid2str(ext.extnID())
                info = {
                    'critical': ext.isCritical(),
                    'name': OIDS.get(oidstr, oidstr)
                    }

                #
                # Add keys to info for extensions we understand.
                #
                # TBD: these might be necessary to validate some certs:
                #
                #  nameConstraints
                #  CRLDistributionPoints
                #
                if info['name'] == 'keyUsage':
                    data = der_decoder.decode(
                        ext.extnValue(),
                        asn1Spec=KeyUsage())[0]
                    info['keyUsage'] = set()
                    for flag in data.FLAGS:
                        if data.has(flag):
                            info['keyUsage'].add(flag)
                    info['keyUsage'] = frozenset(info['keyUsage'])
                elif info['name'] == 'basicConstraints':
                    data = der_decoder.decode(
                        ext.extnValue(), 
                        asn1Spec=BasicConstraints())[0]
                    info['cA'] = bool(data.isCA())
                    if data.getPathLenConstraint() is not None:
                        info['pathLenConstraint'] = int(data.getPathLenConstraint())
                elif info['name'] in ('subjectAltName', 'issuerAltName'):
                    #
                    # This is a list of GeneralName types; we only support the
                    # dNSName field TBD: we should handle the domainComponent
                    # type here, as required by RFC 5280, section 7.3
                    #
                    data = der_decoder.decode(
                        ext.extnValue(), 
                        asn1Spec=SubjectAltName())[0]
                    info['dNSName'] = []
                    for i in range(len(data)):
                        if data.getComponentByPosition(i)\
                                .getComponentByName('dNSName') is not None:
                            info['dNSName'].append(
                                str(
                                    data.getComponentByPosition(i)\
                                        .getComponentByName('dNSName')))
                    if not info['dNSName']:
                        del info['dNSName']
                    else:
                        info['dNSName'] = set(info['dNSName'])

                E.append(info)
        return E

    def getVersion(self):
        return int(str(self.cert.getComponentByName('tbsCertificate')\
                           .getComponentByName('version')))

    def getNotBefore(self):
        return self._getTimeField('notBefore')

    def getNotAfter(self):
	return self._getTimeField('notAfter')

    def _getTimeField(self, field):
        timeclass = self.cert.getComponentByName('tbsCertificate')\
            .getComponentByName('validity').getComponentByName(field)
	timestring = str(timeclass.getComponent())

        #
        # NOTE: the time can be larger than is expressible using a 32-bit
        # Python; e.g., 380731122950Z. In this case, the number of seconds will
        # be correct (2164192190L in this case), but this value won't be
        # convertible to a system time_t value.
        #
	if timeclass.getName() == 'utcTime':
	    if int(timestring[0:2]) < 50:
		timestring = '20' + timestring
	    else:
		timestring = '19' + timestring

	return calendar.timegm(
            time.strptime(
                timestring[0:4]    + ' ' +
                timestring[4:6]    + ' ' +
                timestring[6:8]    + ' ' +
                timestring[8:10]   + ' ' +
                timestring[10:12]  + ' ' +
                timestring[12:14], 
                '%Y %m %d %H %M %S'))

    def _getNameField(self, field):
        "Return a dict with information about the named field."
	name = self.cert.getComponentByName('tbsCertificate')\
            .getComponentByName(field)
        rdnseq = name[0]
        D = {}
        for rdn in rdnseq:
            try:
                atv = rdn[0]
                t, v = atv
                s, encoding = v.getStringAndEncoding()
            except:
                continue

            oidstr = oid2str(t)
            name = OIDS.get(oidstr, oidstr)
            D[name] = s
            D[name + ":encoding"] = encoding
            D[name + ":oid"] = oidstr
        return D

    def getIssuer(self):
        "Return a dict with information about the certificate issuer."
        return self._getNameField("issuer")

    def getSubject(self):
        "Return a dict with information about the certificate subject."
        return self._getNameField("subject")

    def getSignatureAlgorithm(self, as_oid):
        oid = self.cert\
            .getComponentByName('signatureAlgorithm')\
            .getComponentByPosition(0)
        oidstr = oid2str(oid)
        return oidstr if as_oid else OIDS.get(oidstr, oidstr)

    def getSignatureValue(self):
        return self.bits_to_bytes(
            self.cert.getComponentByName('signatureValue'))

    def getPublicKeyInfo(self):
        "Return a dict of info about the certificate's subject public key."
        subPubKeyInfo = self.cert\
            .getComponentByName('tbsCertificate')\
            .getComponentByName('subjectPublicKeyInfo')
        algid = subPubKeyInfo.getComponentByName('algorithm').\
            getComponentByName('algorithm')
        oidstr = oid2str(algid)
        algorithm = OIDS.get(oidstr, oidstr)
        subjectPublicKey = subPubKeyInfo\
            .getComponentByName('subjectPublicKey')
        key = self.bits_to_bytes(subjectPublicKey)
        D = {
            'algorithm_oid': oidstr,
            'algorithm': algorithm,
            'key': key,
            'keylen': len(subjectPublicKey)
            }
        if algorithm == 'rsaEncryption':
            pk = der_decoder.decode(
                key, 
                asn1Spec=RSAPublicKey())[0]
            D['modulus'] = \
                long(pk.getComponentByName('modulus'))
            D['public_exponent'] = \
                long(pk.getComponentByName('publicExponent'))
        return D

    def bits_to_bytes(self, bits):
        "Convert an array of bits to the corresponding byte string."
        # Pad with zeroes to byte boundary
        bits = list(bits) + [0] * ((8 - len(bits) % 8) % 8)
        B = []
        for i in range(0, len(bits), 8):
            B.append(bytes(BITPATTERN_TO_BYTE.get(tuple(bits[i:i+8]))))
        return b''.join(B)

    def getTBSCertificateData(self):
        "Return the raw bytes of the ASN.1 DER tbsCertificate."
        return der_encoder.encode(self.cert.getComponentByName('tbsCertificate'))

    def parseDigestInfo(self, data):
        """
        Get the signature value field and decrypt and parse it to produce the
        digest info for this certificate. Memoized.
        """
        # Parse DigestInfo using BER decoder
        di = ber_decoder.decode(bytes(data), asn1Spec=DigestInfo())[0]
        digest_algorithm_oid = di.getComponentByName('digestAlgorithm')\
            .getComponentByName("algorithm").asTuple()
        oidstr = oid2str(digest_algorithm_oid)
        digest_algorithm = OIDS.get(oidstr, oidstr)
        digest = str(di.getComponentByName("digest"))

        #
        # TBD: we don't handle algorithm parameters, but we should at least
        # verify they are NULL --dmb
        #

        #digest_algorithm_parameters = di.getComponentByName('digestAlgorithm')\
        #    .getComponentByName("parameters")
        
        # Create the tuple of information and return it
        return {
            'algorithm_oid': oidstr,
            'algorithm': digest_algorithm,
            'digest': digest
            }
