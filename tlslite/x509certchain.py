# Authors: 
#   Trevor Perrin
#   Dave Baggett (Arcode Corporation) - cert validation code
#
# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Class representing an X.509 certificate chain."""
from __future__ import print_function
import re
import time
from datetime import datetime

from .utils import cryptomath
from .utils.tackwrapper import *
from .utils.pem import *
from .x509 import X509

SUPPORTED_EXTENSIONS = set(["basicConstraints", "keyUsage", "subjectAltName"])

class X509CertChain(object):
    """This class represents a chain of X.509 certificates.

    @type x509List: list
    @ivar x509List: A list of L{tlslite.x509.X509} instances,
    starting with the end-entity certificate and with every
    subsequent certificate certifying the previous.
    """
    #
    # If a cert's validity date matches within one hour, allow it. This is to
    # accommodate machines that have the incorrect DST settings.
    #
    FUDGE_DST = True

    def __init__(self, x509List=None):
        """Create a new X509CertChain.

        @type x509List: list
        @param x509List: A list of L{tlslite.x509.X509} instances,
        starting with the end-entity certificate and with every
        subsequent certificate certifying the previous.
        """
        if x509List:
            self.x509List = x509List
        else:
            self.x509List = []

    def parsePemList(self, s):
        """Parse a string containing a sequence of PEM certs.

        Raise a SyntaxError if input is malformed.
        """
        x509List = []
        bList = dePemList(s, "CERTIFICATE")
        for b in bList:
            x509 = X509()
            x509.parseBinary(b)
            x509List.append(x509)
        self.x509List = x509List

    def getNumCerts(self):
        """Get the number of certificates in this chain.

        @rtype: int
        """
        return len(self.x509List)

    def getEndEntityPublicKey(self):
        """Get the public key from the end-entity certificate.

        @rtype: L{tlslite.utils.rsakey.RSAKey}
        """
        if self.getNumCerts() == 0:
            raise AssertionError()
        return self.x509List[0].getPublicKey()

    def getFingerprint(self, hashfn="sha1"):
        """Get the hex-encoded fingerprint of the end-entity certificate.

        @type hashfn: str
        @param hashfn: Name of hash function to use (e.g., "sha1")
        @rtype: str
        @return: A hex-encoded fingerprint.
        """
        if self.getNumCerts() == 0:
            raise AssertionError()
        return self.x509List[0].getFingerprint(hashfn)

    def getSubjectCommonNames(self, lowercase=True):
        """Return a list of subject names allowed by the cert: common name and 
        alternate subject names. Note that these names may contain wildcards,
        and my be IDNs (Internationalized Domain Names). The commonName
        component of the subject -- if there is one -- will always be first
        in the list.

        If lowercase is True, names will all be lowercased; this is required by 
        RFC 5280 when comparing names for equality.
        """
        common_names = self.x509List[0].getSubjectCommonNames()
        if lowercase:
            common_names = [name.lower() for name in common_names]
        return common_names
        
    def checkTack(self, tack):
        if self.x509List:
            tlsCert = TlsCertificate(self.x509List[0].bytes)
            if tlsCert.matches(tack):
                return True
        return False
        
    def getTackExt(self):
        """Get the TACK and/or Break Sigs from a TACK Cert in the chain."""
        tackExt = None
        # Search list in backwards order
        for x509 in self.x509List[::-1]:
            tlsCert = TlsCertificate(x509.bytes)
            if tlsCert.tackExt:
                if tackExt:
                    raise SyntaxError("Multiple TACK Extensions")
                else:
                    tackExt = tlsCert.tackExt
        return tackExt
                
    #
    # These are bits; mutiple can be set:
    #
    FLAGS = {
        "success": 0,
        "no_trusted_roots": (1 << 0),
        "not_valid_yet": (1<<1),
        "expired": (1<<2),
        "verify_failed": (1<<3),
        "self_signed": (1<<4),
        "no_trusted_issuer": (1<<5),
        "not_a_ca": (1<<6),
        "issuer_subject_mismatch": (1<<7),
        "unsupported": (1<<8),
        "common_name_mismatch": (1<<9),
        "no_cert_chain": (1<<10),
        "pathlen": (1<<11),
        "internal_error": (1<<12)
        }

    def validate(self, 
                 x509RootCerts, 
                 x509Fingerprints, 
                 x509CommonNames, 
                 skipCommonNameCheck=False, 
                 callback=None, 
                 callbackInfo=None):
        """
        Check the validity of the certificate chain.

        This checks that every certificate in the chain validates with the
        subsequent one, until some certificate validates with (or is identical
        to) one of the passed-in root certificates. Returns a dict with info
        about the validation. The 'success' key in the dict will be True if
        validation succeeded; False otherwise.

        @type x509RootCerts: list of L{tlslite.x509.X509} or dict
        @param x509RootCerts: Root (CA) certificates. This can be either a
        simple list of X509 certificate objects, or a dict mapping canonical
        issuer strings to lists of binary DER strings. The latter is useful in
        low-memory environments because certs are kept in binary form until they
        are needed.
        
        The certificate chain must extend to one of the certificates provided in
        x509RootCerts to be considered valid.

        @type x509Fingerprints: iterable of str
        @param x509Fingerprints: An interable of hex fingerprints of trusted
        root certificates. Fingerprints can be md5, sha1, sha224, sha256,
        sha384, or sha512. (The hash function is automatically determined by the
        fingerprint length.)

        @type x509CommonNames: iterable or str or None
        @param x509CommonNames: set of strings to match end entity commonName
        field (or altSubjectName extension fields) field against. If None, no
        cert will be accepted unless skipCommonNameCheck is True.

        @type skipCommonNameCheck: boolean
        @param skipCommonNameCheck: should the common name check be skipped?

        @type callback: callable
        @param callback: called if the validaton fails; will be passed a dict; e.g.,:

            "success": True,
            "error": X509CertChain.FLAGS['success'],
            "error_text": "",

        The callable may arbitrarily modify the result dict, including changing
        the success value.

        @type callbackInfo: dict
        @param callbackInfo: Extra dict of info to pass to callback function;
        for application-specific purposes. The validator does not look at this
        information; it just passes it along unmodified to the callback.
        """
        if x509Fingerprints:
            x509Fingerprints = set([f.lower() for f in x509Fingerprints])

            #
            # Get set of hash functions to try when looking for trusted
            # fingerprints; for each fingerprint, we can tell what hash was used
            # by the fingerprint length.
            #
            fingerprintHashes = set()
            for f in x509Fingerprints:
                hash = self.HEX_LEN_TO_HASH_TYPE.get(len(f), "sha1")
                fingerprintHashes.add(hash)
        else:
            fingerprintHashes = set()
            x509Fingerprints = set()

        if x509RootCerts is None:
            x509RootCerts = []

        if x509CommonNames is None:
            x509CommonNames = set()

        #
        # NOTE: I based this code on the cert validation code in Forge, which
        # was released into the Public Domain.
        #
        #  http://github.com/digitalbazaar/forge
        #
        # TBD: this still needs work to be fully compliant with RFC 5280. In
        # particular, certificate revocation isn't handled at all right now.
        #
        # -- Dave Baggett, 01-March-2013
        #
        import time

        # Assume failure -- it's safer that way:
        result = {
            "success": False,
            "error": self.FLAGS["internal_error"],
            "error_text": "",
            }

        cert_info = {}
        try:
            # Make sure the chain is nondegenerate.
            chainlen = len(self.x509List)
            if chainlen == 0:
                result = { 
                    "success": False,
                    "error": self.FLAGS["no_cert_chain"],
                    "error_text": "there is no certificate chain",
                    }
                return

            #
            # Info about the current cert; used to populate the response dict in
            # the finally clause below.
            #
            common_names = self.getSubjectCommonNames()
            cert_info = {
                # See note (#) below about why this is set so early:
                "cert_common_name": common_names[0] if common_names else None,
                "cert_common_name_aliases": common_names[1:]
                }

            # See if we have any trusted cert info. If not, we can't validate.
            if not x509RootCerts and not x509Fingerprints:
                result = { 
                    "success": False,
                    "error": self.FLAGS["no_trusted_roots"],
                    "error_text": "no trusted Certificate Authority certificates; " \
                        "can't validate certificate chain"
                    }
                return

            #
            # Make sure the end enitity commonName field is what we expect (the
            # host the user is ostensibly connecting to).
            #
            # IMPORTANT: we intentionally check this before verifying the cert
            # chain, for several reasons:
            #
            # - This check is quite quick, so we can fail certs with bad
            #   commonNames without running a bunch of crypto checks.
            #
            # - It's useful for caller to know -- regardless of other failures
            #   -- whether the server name matches the commonName. For example,
            #   if the host has aliases (hostnames mapping to the same IPs), the
            #   caller may have pick the wrong alias to connect to, and may wish
            #   to know that before attempting to validate the certificate.
            #
            # - More generally, when there are multiple allowable common names
            #   (i.e., x509CommonNames is a set with more than one entry) and
            #   the cert passes the common name check but fails validation, it's
            #   helpful for the caller to know which name to use when printing
            #   failure information.
            #
            # (#) The bottom line is that callers can rely on the
            # cert_common_name field being set to the end entity commonName even
            # if cert validation fails for some other reason.
            #
            common_name_mismatch = False
            if not skipCommonNameCheck:
                validated_names = validate_x509_names(common_names, x509CommonNames)
                if not validated_names:
                    #
                    # Just note failure for now. Actually fail after we've
                    # checked for a trusted cert (below).
                    #
                    common_name_mismatch = True
                else:
                    cert_info["validated_names"] = validated_names

            #
            # Starting with the end entity certificate, validate each cert using
            # the next cert in the chain. We must either end at a trusted CA
            # cert or encounter a trusted cert along the chain for the chain to
            # validate.
            #
            intermediate_certificates = 0
            for i in range(chainlen):
                x509 = self.x509List[i]
    
                #
                # TBD: we should ensure that we haven't seen this exact cert
                # earlier in the certification path.
                #
                # RFC 5280: "A certificate MUST NOT appear more than once in a
                # prospective certification path."
                #

                # Must have previously parsed this x509:
                assert hasattr(x509, "x509")

                # Store some info about the cert (for display to user in case of failure)
                cert_info["cert_version"] = x509.getVersion()
                cert_info["cert_issuer"] = x509.getIssuerAsText()
                cert_info["cert_subject"] = x509.getSubjectAsText()
                cert_info["cert_fingerprint"] = x509.getFingerprint("sha1")
    
                # Get Python time values
                cert_info["cert_not_before"] = not_before = x509.getNotBefore()
                cert_info["cert_not_after"] = not_after = x509.getNotAfter()
                
                #
                # If we encounter a trusted cert, skip the remaining validation.
                #
                # TBD: is this the right thing to do? Maybe it should be an
                # option. We definitely do need a way to allow users to waive
                # cert checks, but skipping the whole rest of the chain might
                # open some security holes; an expert needs to review this...
                #
                if self._is_trusted(x509, x509Fingerprints, x509RootCerts, fingerprintHashes):
                    result = {
                        "success": True,
                        "error": self.FLAGS["success"],
                        "error_text": "",
                        }
                    return
                
                #
                # If we determined that the commonName doesn't match earlier,
                # actually fail the cert now. We wait until now just so we can
                # populate the results with more info about the cert -- and also
                # so that a trusted cert won't fail even if its commonName is
                # wrong.
                #
                if common_name_mismatch:
                    result = {
                        "success": False,
                        "error": self.FLAGS["common_name_mismatch"],
                        "error_text": "forbidden commonName %s; allowed name(s): %s" \
                            % (cert_info['cert_common_name'], x509CommonNames)
                        }
                    return

                #
                # Verify the current time is within the cert's validity range.
                #
                # Currently the time given in error_text is UTC; using
                # "fromtimestamp" instead of "utcfromtimestamp" gives local
                # time.
                #
                now = time.time()
                cert_info["current_time"] = now
                if now < (not_before - 90*1000 if self.FUDGE_DST else 0):
                    result = { 
                        "success": False,
                        "error": self.FLAGS["not_valid_yet"],
                        "error_text": "certificate not valid yet; earliest valid date is %s" \
                            % datetime.utcfromtimestamp(not_before) \
                            .strftime('%Y-%m-%d %H:%M:%S'),
                        }
                    return
                    
                if now > (not_after + 90*1000 if self.FUDGE_DST else 0):
                    result = { 
                        "success": False,
                        "error": self.FLAGS["expired"],
                        "error_text": "certificate expired; latest valid date was %s" % \
                            datetime.utcfromtimestamp(not_after) \
                            .strftime('%Y-%m-%d %H:%M:%S'),
                        }
                    return

                #
                # See if this cert is self-issued.
                #
                # RFC 5280:
                #
                # A certificate is self-issued if the same DN appears in the
                # subject and issuer fields (the two DNs are the same if they
                # match according to the rules specified in Section 7.1). In
                # general, the issuer and subject of the certificates that make
                # up a path are different for each certificate.  However, a CA
                # may issue a certificate to itself to support key rollover or
                # changes in certificate policies.  These self-issued
                # certificates are not counted when evaluating path length or
                # name constraints.
                #
                issuer = x509.getIssuer()
                issuerAsText = x509.getIssuerAsText()
                subject = x509.getSubject()

                if not (issuer is None or subject is None) \
                        and x509.nameEquality(issuer, subject):
                    parent = x509
                    if not parent.verify():
                        result = { 
                            "success": False,
                            "error": self.FLAGS["self_signed"]|self.FLAGS["verify_failed"],
                            "error_text": "self-issued certificate does not self-validate.",
                            }
                        return

                    # Only allow a self-signed cert if it appears in the trusted list
                    trusted = self._is_trusted(x509, x509Fingerprints, x509RootCerts,
                                               fingerprintHashes)
                    if not trusted:
                        result = {
                            "success": False,
                            "error": self.FLAGS["self_signed"]|self.FLAGS["not_a_ca"],
                            "error_text": "self-issued certificate is not trusted",
                            "fingerprint":  x509.getFingerprint()
                            }
                        return
                else:
                    #
                    # Increment count of non-self-signed intermediate
                    # certificates. The end entity (cert 0) does not count.
                    #
                    if i > 0:
                        intermediate_certificates += 1
    
                    #
                    # Verify this cert with its parent. If there's a next cert
                    # in the chain, that's the parent.  Otherwise, we have to
                    # look up the parent in our trusted CA cert list using the
                    # cert's issuer.
                    #
                    if i + 1 < chainlen:
                        # Use parent's public key to verify child's signature
                        parent = self.x509List[i + 1]
                        if not parent.verify(x509):
                            result = { 
                                "success": False,
                                "error": self.FLAGS["verify_failed"],
                                "error_text": "certificate fails parent verification check.",
                                }
                            return
                        else:
                            #print("certificate %s validated by cert %s" % (i, i + 1))
                            pass
                    else: # first cert in chain (chain root)
                        parent = self._get_root_cert(x509, x509RootCerts)    
                        if not parent:
                            # If no CA cert verifies this cert, this cert must itself be trusted
                            parent = x509 if self._is_trusted(
                                x509, 
                                x509Fingerprints, 
                                x509RootCerts, 
                                fingerprintHashes) \
                                else None
                            if not parent:
                                result = { 
                                    "success": False,
                                    "error": self.FLAGS["no_trusted_issuer"],
                                    "error_text": "root certificate could not be validated " \
                                        "by any trusted Certificate Authority certificate.",
                                    }
                                return
    
                        #print("Root cert CA:\n%s" % parent.prettyPrint())

                #
                # Check v3 certificate extensions.
                #
                if parent.getVersion() >= 2: # x509 v3 or above
                    #
                    # Make sure the validating parent certificate is actually a
                    # CA certificate, by checking the basicConstraints
                    # extension. Note that only v3 certs have this extension,
                    # and that some v1 certs are still in wide use. So we need
                    # to allow a v1 cert as the root. See this discussion for
                    # more details:
                    #
                    #   http://unitstep.net/blog/2009/03/16/using-the-basic-constraints-extension-in-x509-v3-certificates-for-intermediate-cas/
                    #
                    parent_bc = parent.getExtension("basicConstraints")
                    # Check cA property:
                    if not parent_bc or (not parent_bc.get('cA') and i != chainlen - 1):
                        result = { 
                            "success": False,
                            "error": self.FLAGS["not_a_ca"],
                            "error_text": "validating certificate is not a " \
                                "Certificate Authority certificate [basicConstraints = %s]." \
                                % parent_bc
                            }
                        return

                    #
                    # Get keyUsage extension value. According to RFC 5280, this
                    # can contain these bits:
                    #
                    #   digitalSignature
                    #   nonRepudiation (a.k.a contentCommitment)
                    #   keyEncipherment
                    #   dataEncipherment
                    #   keyAgreement
                    #   keyCertSign
                    #   cRLSign
                    #   encipherOnly
                    #   decipherOnly
                    #
                    # The only one we currently pay attention to is
                    # keyCertSign. 
                    #
                    # RFC 5280:
                    #
                    #   The keyCertSign bit is asserted when the subject public
                    #   key is used for verifying a signature on public key
                    #   certificates.  If the keyCertSign bit is asserted, then
                    #   the cA bit in the basic constraints extension (section
                    #   4.2.1.10) MUST also be asserted.
                    #
                    parent_ku = parent.getExtension("keyUsage")
                    if parent_ku is not None \
                            and 'keyCertSign' in parent_ku.get('keyUsage', []) \
                            and not parent_bc.get('cA'):
                        result = { 
                            "success": False,
                            "error": self.FLAGS["not_a_ca"],
                            "error_text": "validating parent certificate specifies " \
                                "keyUsage:keyCertSign, but cA is FALSE.",
                            }
                        return

                    #
                    # Check validating parent's pathlen constraint. This tells
                    # you the number of intermediate certificates that may
                    # precede (be validated by) this CA cert. Note that the end
                    # entity (cert 0, in our case) does not count towards the
                    # pathlen.
                    #
                    # RFC 5280:
                    #
                    #   The pathLenConstraint field is meaningful only if the cA
                    #   boolean is asserted and the key usage extension asserts
                    #   the keyCertSign bit (section 4.2.1.3).  In this case, it
                    #   gives the maximum number of non-self-issued intermediate
                    #   certificates that may follow this certificate in a valid
                    #   certification path.  A certificate is self-issued if the
                    #   DNs that appear in the subject and issuer fields are
                    #   identical and are not empty.  (Note: The last
                    #   certificate in the certification path is not an
                    #   intermediate certificate, and is not included in this
                    #   limit.  Usually, the last certificate is an end entity
                    #   certificate, but it can be a CA certificate.)  A
                    #   pathLenConstraint of zero indicates that only one more
                    #   certificate may follow in a valid certification path.
                    #   Where it appears, the pathLenConstraint field MUST be
                    #   greater than or equal to zero.  Where pathLenConstraint
                    #   does not appear, no limit is imposed.
                    #
                    pathlen = parent_bc.get('pathLenConstraint')
                    if parent_bc.get('cA') and pathlen is not None:
                        if pathlen < intermediate_certificates:
                            result = { 
                                "success": False,
                                "error": self.FLAGS["pathlen"],
                                "error_text": "validating parent certificate violates " \
                                    "pathlen=%s constraint" % pathlen
                                }
                            return
                    
                #
                # TBD: Verify that this certificate has not been revoked by
                # checking the CRL. See RFC 5280, section 6.3 for details.
                #
    
                #
                # Check for matching issuer/subject.
                #
                parent_subject = parent.getSubject()
                if not x509.nameEquality(issuer, parent_subject):
                    result = { 
                        "success": False,
                        "error": self.FLAGS["issuer_subject_mismatch"],
                        "error_text": "validating (parent) certficate issuer (%s) " \
                            "does not match certificate subject (%s)." \
                            % (issuerAsText, parent.getSubjectAsText())
                        }
                    return

                # 
                # TBD: I have no idea what this means; need an expert here.
                #   -- Dave Baggett
                #
                # RFC 5280:
                #
                # If the certificate is self-issued and not the final
                # certificate in the chain, skip this step, otherwise...
                #
                # 6.1.3 (c) Verify that the subject name is within one of the
                # permitted subtrees of X.500 distinguished names and that each
                # of the alternative names in the subjectAltName extension
                # (critical or non-critical) is within one of the permitted
                # subtrees for that name type. Verify that the subject name is
                # not within one of the excluded subtrees for X.500
                # distinguished names and none of the subjectAltName extension
                # names are excluded for that name type.
                #
    
                #
                # Check for a crticial policy extension. If we find one we don't
                # handle, reject the cert since we don't know how to validate
                # the extension and doing so is required.
                #
                if x509.getVersion() >= 2: # x509 v3 or above
                    for ext in x509.getCriticalExtensions():
                        if ext.get('name') not in SUPPORTED_EXTENSIONS:
                            result = { 
                                "success": False,
                                "error": self.FLAGS["unsupported"],
                                "error_text": "unsuported critical extension " \
                                    + ext.get('name') + " in certificate",
                                }
                            return
    
            # Cert validated OK
            result = {
                "success": True,
                "error": self.FLAGS["success"],
                "error_text": "",
                }

        except Exception as e:
            import sys
            import traceback
            print("X509CertChain.validate: caught exception; traceback follows:")
            traceback.print_exc(file=sys.stdout)
            result = { 
                "success": False,
                "error": self.FLAGS["internal_error"],
                "error_text": "internal error: %s" % e,
                }
            raise e
            return

        finally:
            result['allowed_common_names'] = x509CommonNames
            result.update(cert_info)
            if not result["success"] and callable(callback):
                if callbackInfo is not None:
                    result = callback(result, callbackInfo)
                else:
                    result = callback(result)
            self._set_result_flags(result)
            #print("X509CertChain.validate returning %s" % result)
            return result

    # Mapping from hash length to hash type:
    HEX_LEN_TO_HASH_TYPE = { 
        32: 'md5', 
        40: 'sha1', 
        56: 'sha224', 
        64: 'sha256', 
        96: 'sha384', 
        128: 'sha512' 
        }

    @classmethod
    def _is_trusted(C, cert, x509Fingerprints, x509RootCerts, fingerprintHashes):
        "Determine whether or not the provided cert is trusted."
        # See if this cert's fingerprint is in the trusted fingerprints set
        for hash in fingerprintHashes:
            cert_fingerprint = cert.getFingerprint(hash)
            if cert_fingerprint in x509Fingerprints:
                #print("%s fingerprint of cert (%s) is in x509Fingerprints list" % \
                #(hash, cert_fingerprint))
                return True

        # See if this cert is in the trusted certs list; just compare raw binary DER bytes.
        cert_binary = cert.getDER()
        matched_a_root_cert = False
        if isinstance(x509RootCerts, (tuple, list)):
            for c in x509RootCerts:
                if c.getDER() == cert_binary:
                    matched_a_root_cert = True
                    break
        elif isinstance(x509RootCerts, dict):
            for issuer, cacerts in x509RootCerts.iteritems():
                for ca in cacerts:
                    if isinstance(ca, type(bytes())):
                        # Cert is still stored as raw DER binary:
                        ca_cert_binary = ca
                    else:
                        # Cert was previously parsed into an X509 object:
                        ca_cert_binary = ca.getDER()

                    if ca_cert_binary == cert_binary:
                        matched_a_root_cert = True
                        break

        if matched_a_root_cert:
            if cert.verify():
                return True
            else:
                print("cert is in x509RootCerts, but the cert itself fails to verify, "
                      "so it's disallowed")
                return False

        return False

    @classmethod
    def _get_root_cert(C, x509, x509RootCerts):
        "Return the CA cert that signed the provided cert, or None."
        if isinstance(x509RootCerts, (tuple, list)):
            #
            # We have a list or tuple of root certs. In this case, we just
            # compare each cert to the cert in question.
            #
            issuer = x509.getIssuer()
            parent = None
            for ca in x509RootCerts:
                if x509.nameEquality(ca.getIssuer(), issuer):
                    #
                    # Make sure the CA cert self-verifies so we know it hasn't
                    # been tampered with.
                    #
                    if not ca.verify():
                        continue

                    # Try to validate this cert with trusted CA cert:
                    if ca.verify(x509):
                        return ca
        elif isinstance(x509RootCerts, dict):
            #
            # We have a dict of root certs. In this case, the key is the
            # canonical issuer string and the value is the DER binary of the
            # cert.
            #
            issuer = x509.getIssuerAsText()

            # Parse all the certs with this issuer:
            parsed = C._get_root_certs_from_dict(x509RootCerts, issuer)
            if parsed:
                # See if any CA cert with this issuer validates this cert
                for ca in parsed:
                    #
                    # Make sure the CA cert self-verifies so we know it hasn't
                    # been tampered with.
                    #
                    if not ca.verify():
                        continue

                    # Try to validate this cert with trusted CA cert:
                    if ca.verify(x509):
                        return ca

            print("no CA cert found for issuer %s" % issuer)
        return None

    @staticmethod
    def _get_root_certs_from_dict(x509RootCerts, issuer):
        """Get the list of certs matching a particular issuer; only appropriate
        when x509RootCerts is in dict form. This will parse certs that are still
        in binary DER form, and thus can take a nontrivial amount of time."""
        assert isinstance(x509RootCerts, dict)
        unparsed = x509RootCerts.get(issuer)
        parsed = []
        if unparsed and isinstance(unparsed[0], type(bytes())):
            for ca in unparsed:
                # Create an X509 object by parsing the raw DER binary for this cert:
                parsed.append(X509(ca, pem=False))
            #print("parsed %s certs with issuer %s" % (len(parsed), issuer))
            x509RootCerts[issuer] = parsed
        else:
            parsed = unparsed # already parsed earlier
        return parsed
        
    @classmethod
    def _set_result_flags(C, result):
        for flag, value in C.FLAGS.items():
            if value:
                if result.get("error", 0) & value:
                    result[flag] = True

def validate_x509_names(actual_names, allowed_names, no_degenerate_wildcard_match=False):
    """Validate the commonName field against the allowed names. Returns a list
    of matching allowed names. (The list may contain more than one name if the
    cert is a wildcard cert, or if the cert specifies alternate subject names
    which also appear in the list of names allowed for this connection.)
    
    From RFC 2818:

      Names may contain the wildcard character * which is considered to match
      any single domain name component or component fragment. E.g., *.a.com
      matches foo.a.com but not bar.foo.a.com. f*.com matches foo.com but not
      bar.com.

    See also the discussion here: http://nils.toedtmann.net/pub/subjectAltName.txt

      So "loose matching" like www.test.example.com=*.example.com or
      www.example.com=*.com or example.com=* violates RFC 2818.

      And though standard compliant, matching "generic wildcards" like top- or
      second-level wildcards (museum.=*, example.com=*.com) or third-level
      wildcards within generic SLDs (example.co.uk=*.co.uk) should be considered
      bad practice.

    Despite this, we do allow *.example.com to match example.com (no subdomain)
    unless no_degenerate_wildcard_matches is True.

    Note also that we may encounter IDNs (Internationalized Domain Names).
    According to RFC 5280, these must have been converted to plain ASCII using
    ACE or "punycode" by the certificate issuer, so these need no special
    treatment here.

    We assume that names have all been lowercased; RFC 5280 stipluates that
    common name comparisons are to be case-insensitive."""
    A = []
    for actual_name in actual_names:
        if actual_name.find('*') >= 0:
            #
            # Don't match any wildcarded spec that contains fewer than two dots;
            # e.g.:
            #
            #   *
            #   *.com
            #   *.ru
            #
            # We also disallow the * appearing in the last two components of the
            # name:
            #
            #   mail.ex*.com
            #   mail.example.*
            #
            # We do allow sub-sub-domain wildcards, though. I don't see anything
            # wrong with these, for example:
            #
            #   *.mail.example.com
            #   *.mail.example.co.uk
            #
            # We also allow multiple wildcards, as long as they are in
            # acceptable components:
            #
            #   m*.y*hoo.co.uk
            #
            # We allow *.example.com to match example.com unless
            # no_degenerate_wildcard.match is True.
            #
            if actual_name.count('.') < 2:
                #print("wildcarded commonName or altSubjectName '%s' is too broad; ignoring" \
                #          % actual_name)
                continue
            components = actual_name.split('.')
            if components[-1].find('*') >= 0 or components[-2].find('*') >= 0:
                #print("wildcarded commonName or altSubjectName '%s' is too broad; ignoring" \
                #          % actual_name)
                continue

            #
            # Unless no_degenerate_wildcard_match is True, allow a leading *. to
            # match nothing at all. This isn't technically correct, but it's
            # what OpenSSL does, and what some major servers assume.
            #
            for prefix in ('', '*.'):
                if no_degenerate_wildcard_match and prefix == '*.':
                    continue

                lp = len(prefix)
                if lp and actual_name.find(prefix) > 0:
                    continue

                # Escape any characters in the common name that are possible regex operators
                name_regex = "^" + re.sub(
                    r"([.|+?(){}<>^$#\[\]\\])", 
                    lambda match: "\\" + match.group(0),
                    actual_name[lp:]).replace("*", "[^.]*") + "$"

                # See which names match the regex:
                A.extend([allowed
                          for allowed in allowed_names
                          if re.match(name_regex, allowed)])
        else:
            if actual_name in allowed_names:
                A.append(actual_name)
    return A
