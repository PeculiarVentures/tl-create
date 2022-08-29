# tl-create

[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/tl-create/master/LICENSE)
[![Build Status](https://travis-ci.org/PeculiarVentures/tl-create.svg?branch=master)](https://travis-ci.org/PeculiarVentures/tl-create)
[![NPM version](https://badge.fury.io/js/tl-create.svg)](http://badge.fury.io/tl-create)

[![NPM](https://nodei.co/npm-dl/tl-create.png?months=2&height=2)](https://nodei.co/npm/tl-create/)

A cross platform command line tool to create a X.509 trust list from various trust stores.

There are various organizations that produce lists of certificates that they believe should be trusted for one thing or another. These include:
- Mozilla [list](http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1) 
- Microsoft [list](http://technet.microsoft.com/en-us/library/cc751157.aspx), 
- Apple [list](http://www.apple.com/certificateauthority/ca_program.html)
- European Union "Trust Service Providers" [list](https://ec.europa.eu/digital-agenda/en/eu-trusted-lists-certification-service-providers)

Each of these lists have their own formats, this tool parses the lists provided by these other organizations and extracts the certificates that meet the specified criteria (for "email" as an example) and produces a PEM certificate bag these certificates.

For example to extract the roots that are trusted for email, code and web from both the EU Trust List and the Mozilla list the command would look like this:

```
node src/bin/tl-create.js --eutl --mozilla --for 'EMAIL_PROTECTION,CODE_SIGNING' --format pem roots.pem
```

This would produce a file that looked something like this:
```
 Country: UK
 Operator: European Commission
 Source: EUTL
 -----BEGIN CERTIFICATE-----
 ...
 ...
 -----END CERTIFICATE-----
 Operator: DigiCert, Inc
 For: email, www, code
 Source: Mozilla
 -----BEGIN CERTIFICATE-----
 ...
 ...
 -----END CERTIFICATE-----
```
## Usage
### Extract all Microsoft Roots
```
node src/bin/tl-create.js --microsoft --format pem roots.pem
```

#### Valid Microsoft trust purposes 
```
  SERVER_AUTH
  CLIENT_AUTH
  CODE_SIGNING
  EMAIL_PROTECTION
  IPSEC_END_SYSTEM
  IPSEC_TUNNEL
  IPSEC_USER
  TIME_STAMPING
  OCSP_SIGNING
  IPSEC_PROTECTION
  DOCUMENT_SIGNING
  EFS_CRYPTO
```

### Extract all Mozilla Roots
```
node src/bin/tl-create.js --mozilla --format pem roots.pem
```

#### Valid Mozilla trust purposes 
```
  DIGITAL_SIGNATURE
  NON_REPUDIATION
  KEY_ENCIPHERMENT
  DATA_ENCIPHERMENT
  KEY_AGREEMENT
  KEY_CERT_SIGN
  CRL_SIGN
  SERVER_AUTH
  CLIENT_AUTH
  CODE_SIGNING
  EMAIL_PROTECTION
  IPSEC_END_SYSTEM
  IPSEC_TUNNEL
  IPSEC_USER
  TIME_STAMPING
  STEP_UP_APPROVED
```

### Extract all Apple Roots
```
node src/bin/tl-create.js --apple --format pem roots.pem
```

### Extract all AATL Roots
```
node src/bin/tl-create.js --aatl --format pem roots.pem
```

#### Valid AATL trust purposes 
```
  ROOT
  CERTIFIED_DOCUMENTS
  DYNAMIC_CONTENT
  JAVASCRIPT
```

### Extract all EUTL Roots
```
node src/bin/tl-create.js --eutl --format pem roots.pem
```

### Extract only SERVER_AUTH certificates from Mozilla and Microsoft

```
node src/bin/tl-create.js --mozilla --microsoft --for "SERVER_AUTH" --format pem roots.pem
```

**NOTE**: The default is ALL purposes 

### Available output formats 
```
js
pkijs
pem
files
```

The "files" format is intended to store all certificates in separate files under specific directory. For example if a certificate exists in Mozilla Trust List and has "SubjectKeyIdentifier" equal to "ABABABABABABABBB" the certificate content would be stored under "mozilla/ABABABABABABABBB". So, for Mozilla Trust List root directory would be "mozilla", for Microsoft - "microsoft", for Apple - "apple", for Cisco - "cisco".

**NOTE**: Default output format is 'js'

## Install

```
git clone https://github.com/PeculiarVentures/tl-create.git
cd tl-create
npm install -g
``` 


## Bug Reporting
Please report bugs either as pull requests or as issues in the issue tracker. tl-create has a full disclosure vulnerability policy. Please do NOT attempt to report any security vulnerability in this code privately to anybody.

## TODO
* Add the [Oracle Root Program](http://www.oracle.com/technetwork/java/javase/javasecarootcertsprogram-1876540.html)

## Related
- [CommanderJS](https://github.com/tj/commander.js)
- [PKIjs](https://pkijs.org)
- [CATT](https://github.com/kirei/catt)
- [tlbrowser](http://tlbrowser.tsl.website)
- [autoroot update](https://unmitigatedrisk.com/?p=259)
