# tl-create

[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/tl-create/master/LICENSE)
[![Build Status](https://travis-ci.org/PeculiarVentures/tl-create.svg?branch=master)](https://travis-ci.org/PeculiarVentures/tl-create)
[![NPM version](https://badge.fury.io/js/tl-create.png)](http://badge.fury.io/tl-create)


Node command line tool to create a X.509 trust list from various trust stores

There are various organizations that produce lists of certificates that they believe should be trusted for one thing or another. The most used is the Mozilla [list](http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1) but there are more, such as the Microsoft [list](http://technet.microsoft.com/en-us/library/cc751157.aspx), and the European Union "Trust Service Providers" [list](https://ec.europa.eu/digital-agenda/en/eu-trusted-lists-certification-service-providers).

Each of these lists have their own formats, this tool parses the lists provided by these other organizations and extracts the certificates that meet the specified criteria (for "email" as an example) and produces a PEM certificate bag these certificates.

For example to extract the roots that are trusted for email, code and web from both the EU Trust List and the Mozilla list the command would look like this:

```
node tl-create --eutl --mozilla --for 'EMAIL_PROTECTION,CODE_SIGNING' --format pem roots.pem
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

Valid Mozilla trust purposes 
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

**NOTE**: The default is ALL purposes 

Available ouptut format 
```
js
pkijs
pem
```
Default ouput format is 'js'

## Install

```
git clone https://github.com/PeculiarVentures/tl-create.git
cd tl-create
npm install -g
``` 


## Bug Reporting
Please report bugs either as pull requests or as issues in the issue tracker. tl-create has a full disclosure vulnerability policy. Please do NOT attempt to report any security vulnerability in this code privately to anybody.

## TODO
* Add the [Apple Root Progam](http://www.apple.com/certificateauthority/ca_program.html)
* Add the [Adobe Root Program](http://trustlist.adobe.com/eutl12.acrobatsecuritysettings)
* Add the [Oracle Root Program](http://www.oracle.com/technetwork/java/javase/javasecarootcertsprogram-1876540.html)

## Related
- [CommanderJS](https://github.com/tj/commander.js)
- [PKIjs](https://pkijs.org)
- [CATT](https://github.com/kirei/catt)
- [tlbrowser](http://tlbrowser.tsl.website)
- [autoroot update](https://unmitigatedrisk.com/?p=259)
