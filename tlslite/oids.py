# Authors: 
#   Dave Baggett (Arcode Corporation)
#
# See the LICENSE file for legal information regarding use of this file.
#
# OIDs relevant to X.509 certificate parsing and validation.
#
# See: http://www.alvestrand.no/cgi-bin/hta/oidwordsearch
#
OIDS = {
    "{ 0.9.2342.19200300.100.1.25 }": "domainComponent", # RFC 4514
    "{ 0.9.2342.19200300.100.1.1 }": "userId", # RFC 4514
    "{ 1.2.840.10040.4.1 }": "id-dsa",
    "{ 1.2.840.10040.4.3 }": "id-dsa-with-sha1",
    # Elliptic Curve public key:
    "{ 1.2.840.10045.2.1 }": "id-ecPublicKey",
    # ECDSA signature with SHA-1:
    "{ 1.2.840.10045.4.1 }": "ecdsa-with-SHA1",
    # http://tools.ietf.org/html/draft-ietf-pkix-sha2-dsa-ecdsa-10:
    "{ 1.2.840.10045.4.3.1 }": "ecdsa-with-SHA224",
    "{ 1.2.840.10045.4.3.2 }": "ecdsa-with-SHA256",
    "{ 1.2.840.10045.4.3.3 }": "ecdsa-with-SHA384",
    "{ 1.2.840.10045.4.3.4 }": "ecdsa-with-SHA512",
    # Diffie-Hellman public key:
    "{ 1.2.840.10046.2.1 }": "dhpublicnumber",
    "{ 1.2.840.113533.7.65.0 }": "entrustVersionExtension",
    # RSA public keys:
    "{ 1.2.840.113549.1.1.1 }": "rsaEncryption",
    "{ 1.2.840.113549.1.1.10 }": "RSASSA-PSS",
    "{ 1.2.840.113549.1.1.11 }": "sha256WithRSAEncryption",
    "{ 1.2.840.113549.1.1.12 }": "sha384WithRSAEncryption",
    "{ 1.2.840.113549.1.1.13 }": "sha512WithRSAEncryption",
    # RSA signature generated with MD2 hash:
    "{ 1.2.840.113549.1.1.2 }": "md2WithRSAEncryption",
    "{ 1.2.840.113549.1.1.3 }": "md4WithRSAEncryption",
    # RSA signature generated with MD5 hash:
    "{ 1.2.840.113549.1.1.4 }": "md5WithRSAEncryption",
    # RSA signature generated with SHA1 hash:
    "{ 1.2.840.113549.1.1.5 }": "sha1WithRSAEncryption",
    "{ 1.2.840.113549.1.1.6 }": "rsaOAEPEncryptionSET",
    "{ 1.2.840.113549.1.1.7 }": "id-RSAES-OAEP",
    "{ 1.2.840.113549.1.9 }": "email",
    "{ 1.2.840.113549.1.9.1 }": "emailAddress",
    "{ 1.2.840.113549.2.2 }": "md2", # MD2 hash function
    "{ 1.2.840.113549.2.26 }": "id-sha1",
    "{ 1.2.840.113549.2.5 }": "md5", # MD5 hash function
    "{ 1.3.14.3.2.10 }": "desMAC",
    "{ 1.3.14.3.2.11 }": "rsaSignature",
    "{ 1.3.14.3.2.12 }": "dsa",
    "{ 1.3.14.3.2.13 }": "dsaWithSHA",
    "{ 1.3.14.3.2.14 }": "mdc2WithRSASignature",
    "{ 1.3.14.3.2.15 }": "shaWithRSASignature",
    "{ 1.3.14.3.2.16 }": "dhWithCommonModulus",
    "{ 1.3.14.3.2.17 }": "desEDE",
    "{ 1.3.14.3.2.18 }": "sha",
    "{ 1.3.14.3.2.19 }": "mdc-2",
    "{ 1.3.14.3.2.2 }": "md4WithRSA",
    "{ 1.3.14.3.2.20 }": "dsaCommon",
    "{ 1.3.14.3.2.21 }": "dsaCommonWithSHA",
    "{ 1.3.14.3.2.22 }": "rsaKeyTransport",
    "{ 1.3.14.3.2.23 }": "keyed-hash-seal",
    "{ 1.3.14.3.2.24 }": "md2WithRSASignature",
    "{ 1.3.14.3.2.25 }": "md5WithRSASignature",
    "{ 1.3.14.3.2.26 }": "sha-1",
    "{ 1.3.14.3.2.27 }": "dsa-sha1",
    "{ 1.3.14.3.2.28 }": "dsa-sha1-common-parameters",
    "{ 1.3.14.3.2.29 }": "sha1-with-RSA-signature",
    "{ 1.3.14.3.2.3 }": "md5WithRSA",
    "{ 1.3.14.3.2.4 }": "md4WithRSAEncryption",
    "{ 1.3.14.3.2.6 }": "desECB",
    "{ 1.3.14.3.2.7 }": "desCBC",
    "{ 1.3.14.3.2.8 }": "desOFB",
    "{ 1.3.14.3.2.9 }": "desCFB",

    # Microsoft:
    # http://support.microsoft.com/support/kb/articles/Q291/0/10.ASP :
    "{ 1.3.6.1.4.1.311.20.2 }": "certificateTemplateNameDomainController",
    # http://support.microsoft.com/kb/287547?wa=wsignin1.0 :
    "{ 1.3.6.1.4.1.311.21.1 }": "certificateCounter",

    # for EV certs:
    "{ 1.3.6.1.4.1.311.60.2.1.1 }": \
        "jurisdictionOfIncorporationLocalityName",
    "{ 1.3.6.1.4.1.311.60.2.1.2 }": \
        "jurisdictionOfIncorporationStateOrProvinceName",
    "{ 1.3.6.1.4.1.311.60.2.1.3 }": \
        "jurisdictionOfIncorporationCountryName",

    # private certificate extensions:
    "{ 1.3.6.1.5.5.7.1.1 }": "id-pe-authorityInfoAccess",
    "{ 1.3.6.1.5.5.7.1.12 }": "id-pe-logotype",
    "{ 1.3.6.1.5.5.7.1.2 }": "id-pe-biometricInfo",
    "{ 1.3.6.1.5.5.7.1.3 }": "id-pe-qcStatements",

    # KEA key:
    "{ 2.16.840.1.101.2.1.1.22 }": "id-keyExchangeAlgorithm",

    "{ 2.16.840.1.101.3.4.2.1 }": "sha-256",
    "{ 2.16.840.1.101.3.4.2.2 }": "sha-384",
    "{ 2.16.840.1.101.3.4.2.3 }": "sha-512",
    "{ 2.16.840.1.113730.1.1 }": "certificateType",
    "{ 2.16.840.1.113730.1.13 }": "comment",
    "{ 2.23.42.7.0 }": "id-set-hashedRootKey",
    "{ 2.5.29.1 }": "oldAuthorityKeyIdentifier",
    "{ 2.5.29.14 }": "subjectKeyIdentifier",
    "{ 2.5.29.15 }": "keyUsage",
    "{ 2.5.29.16 }": "privateKeyUsagePeriod",
    "{ 2.5.29.17 }": "subjectAltName",
    "{ 2.5.29.18 }": "issuerAltName",
    "{ 2.5.29.19 }": "basicConstraints",
    "{ 2.5.29.2 }": "oldPrimaryKeyAttributes",
    "{ 2.5.29.20 }": "cRLNumber",
    "{ 2.5.29.21 }": "reasonCode",
    "{ 2.5.29.23 }": "holdInstructionCode",
    "{ 2.5.29.24 }": "invalidityDate",
    "{ 2.5.29.27 }": "deltaCRLIndicator",
    "{ 2.5.29.28 }": "issuingDistributionPoint",
    "{ 2.5.29.29 }": "certificateIssuer",
    "{ 2.5.29.3 }": "certificatePolicies",
    "{ 2.5.29.30 }": "nameConstraints",
    "{ 2.5.29.31 }": "cRLDistributionPoints",
    "{ 2.5.29.32 }": "certificatePolicies",
    "{ 2.5.29.32.0 }": "anyPolicy",
    "{ 2.5.29.33 }": "policyMappings",
    "{ 2.5.29.35 }": "authorityKeyIdentifier",
    "{ 2.5.29.36 }": "policyConstraints",
    "{ 2.5.29.37 }": "extendedKeyUsage",
    "{ 2.5.29.4 }": "primaryKeyUsageRestriction",
    "{ 2.5.29.46 }": "freshestCRL",
    "{ 2.5.29.54 }": "inhibitAnyPolicy",
    "{ 2.5.4.0 }": "objectClass",
    "{ 2.5.4.1 }": "aliasedEntryName",
    "{ 2.5.4.10 }": "organizationName",
    "{ 2.5.4.11 }": "organizationalUnitName",
    "{ 2.5.4.11.1 }": "collectiveOrganizationalUnitName",
    "{ 2.5.4.12 }": "title",
    "{ 2.5.4.13 }": "description",
    "{ 2.5.4.14 }": "searchGuide",
    "{ 2.5.4.15 }": "businessCategory",
    "{ 2.5.4.16 }": "postalAddress",
    "{ 2.5.4.16.1 }": "collectivePostalAddress",
    "{ 2.5.4.17 }": "postalCode",
    "{ 2.5.4.17.1 }": "collectivePostalCode",
    "{ 2.5.4.18 }": "postOfficeBox",
    "{ 2.5.4.18.1 }": "collectivePostOfficeBox",
    "{ 2.5.4.19 }": "physicalDeliveryOfficeName",
    "{ 2.5.4.19.1 }": "collectivePhysicalDeliveryOfficeName",
    "{ 2.5.4.2 }": "knowledgeinformation",
    "{ 2.5.4.20 }": "telephoneNumber",
    "{ 2.5.4.20.1 }": "collectiveTelephoneNumber",
    "{ 2.5.4.21 }": "telexNumber",
    "{ 2.5.4.21.1 }": "collectiveTelexNumber",
    "{ 2.5.4.22 }": "telexTerminalIdentifier",
    "{ 2.5.4.22.1 }": "collectiveTelexTerminalIdentifer",
    "{ 2.5.4.23 }": "facsimileTelephoneNumber",
    "{ 2.5.4.23.1 }": "collectiveFacsimileTelephoneNumber",
    "{ 2.5.4.24 }": "x121Address",
    "{ 2.5.4.25 }": "internationalISDNNumber",
    "{ 2.5.4.25.1 }": "collectiveInternationalISDNNumber",
    "{ 2.5.4.26 }": "registeredAddress",
    "{ 2.5.4.27 }": "destinationIndicator",
    "{ 2.5.4.28 }": "preferredDeliveryMethod",
    "{ 2.5.4.29 }": "presentationAddress",
    "{ 2.5.4.3 }": "commonName",
    "{ 2.5.4.30 }": "supportedApplicationContext",
    "{ 2.5.4.31 }": "member",
    "{ 2.5.4.32 }": "owner",
    "{ 2.5.4.33 }": "roleOccupant",
    "{ 2.5.4.34 }": "seeAlso",
    "{ 2.5.4.35 }": "userPassword",
    "{ 2.5.4.36 }": "userCertificate",
    "{ 2.5.4.37 }": "cACertificate",
    "{ 2.5.4.38 }": "authorityRevocationList",
    "{ 2.5.4.39 }": "certificateRevocationList",
    "{ 2.5.4.4 }": "surname",
    "{ 2.5.4.40 }": "crossCertificatePair",
    "{ 2.5.4.41 }": "name",
    "{ 2.5.4.42 }": "givenName",
    "{ 2.5.4.43 }": "initials",
    "{ 2.5.4.44 }": "generationQualifier",
    "{ 2.5.4.45 }": "uniqueIdentifier",
    "{ 2.5.4.46 }": "dnQualifier",
    "{ 2.5.4.47 }": "enhancedSearchGuide",
    "{ 2.5.4.48 }": "protocolInformation",
    "{ 2.5.4.49 }": "distinguishedName",
    "{ 2.5.4.5 }": "serialNumber",
    "{ 2.5.4.50 }": "uniqueMember",
    "{ 2.5.4.51 }": "houseIdentifier",
    "{ 2.5.4.52 }": "supportedAlgorithms",
    "{ 2.5.4.53 }": "deltaRevocationList",
    "{ 2.5.4.58 }": "attributeCertificate",
    "{ 2.5.4.6 }": "countryName",
    "{ 2.5.4.65 }": "psuedonym",
    "{ 2.5.4.7 }": "localityName",
    "{ 2.5.4.7.1 }": "collectiveLocalityName",
    "{ 2.5.4.8 }": "stateOrProvinceName",
    "{ 2.5.4.8.1 }": "collectiveStateOrProvinceName",
    "{ 2.5.4.9 }": "streetAddress",
    "{ 2.5.4.9.1 }": "collectiveStreetAddress"
}

OID_short_names = {
    "{ 2.5.4.10 }": "O", # organizationName
    "{ 2.5.4.11 }": "OU", # organizationalUnitName
    "{ 2.5.4.3 }": "CN", # commonName
    "{ 2.5.4.4 }": "SN", # surname
    "{ 2.5.4.42 }": "GN", # givenName
    "{ 2.5.4.6 }": "C", # countryName
    "{ 2.5.4.7 }": "L", # localityName
    "{ 2.5.4.8 }": "ST", # stateOrProvinceName
    "{ 2.5.4.9 }": "STREET", # streetAddress
    "{ 0.9.2342.19200300.100.1.25 }": "DC", # domainComponent
    "{ 0.9.2342.19200300.100.1.1 }": "UID" # userId
}
