var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
/// <reference types="xml-core" />
var tl_create;
(function (tl_create) {
    var MozillaAttributes = {
        CKA_CLASS: "CKA_CLASS",
        CKA_TOKEN: "CKA_TOKEN",
        CKA_PRIVATE: "CKA_PRIVATE",
        CKA_MODIFIABLE: "CKA_MODIFIABLE",
        CKA_LABEL: "CKA_LABEL",
        CKA_CERTIFICATE_TYPE: "CKA_CERTIFICATE_TYPE",
        CKA_SUBJECT: "CKA_SUBJECT",
        CKA_ID: "CKA_ID",
        CKA_ISSUER: "CKA_ISSUER",
        CKA_SERIAL_NUMBER: "CKA_SERIAL_NUMBER",
        CKA_EXPIRES: "CKA_EXPIRES",
        CKA_VALUE: "CKA_VALUE",
        CKA_NSS_EMAIL: "CKA_NSS_EMAIL",
        CKA_CERT_SHA1_HASH: "CKA_CERT_SHA1_HASH",
        CKA_CERT_MD5_HASH: "CKA_CERT_MD5_HASH",
        CKA_TRUST_DIGITAL_SIGNATURE: "CKA_TRUST_DIGITAL_SIGNATURE",
        CKA_TRUST_NON_REPUDIATION: "CKA_TRUST_NON_REPUDIATION",
        CKA_TRUST_KEY_ENCIPHERMENT: "CKA_TRUST_KEY_ENCIPHERMENT",
        CKA_TRUST_DATA_ENCIPHERMENT: "CKA_TRUST_DATA_ENCIPHERMENT",
        CKA_TRUST_KEY_AGREEMENT: "CKA_TRUST_KEY_AGREEMENT",
        CKA_TRUST_KEY_CERT_SIGN: "CKA_TRUST_KEY_CERT_SIGN",
        CKA_TRUST_CRL_SIGN: "CKA_TRUST_CRL_SIGN",
        CKA_TRUST_SERVER_AUTH: "CKA_TRUST_SERVER_AUTH",
        CKA_TRUST_CLIENT_AUTH: "CKA_TRUST_CLIENT_AUTH",
        CKA_TRUST_CODE_SIGNING: "CKA_TRUST_CODE_SIGNING",
        CKA_TRUST_EMAIL_PROTECTION: "CKA_TRUST_EMAIL_PROTECTION",
        CKA_TRUST_IPSEC_END_SYSTEM: "CKA_TRUST_IPSEC_END_SYSTEM",
        CKA_TRUST_IPSEC_TUNNEL: "CKA_TRUST_IPSEC_TUNNEL",
        CKA_TRUST_IPSEC_USER: "CKA_TRUST_IPSEC_USER",
        CKA_TRUST_TIME_STAMPING: "CKA_TRUST_TIME_STAMPING",
        CKA_TRUST_STEP_UP_APPROVED: "CKA_TRUST_STEP_UP_APPROVED",
        CKT_NSS_TRUSTED_DELEGATOR: "CKT_NSS_TRUSTED_DELEGATOR",
        CKT_NSS_MUST_VERIFY_TRUST: "CKT_NSS_MUST_VERIFY_TRUST",
        CKT_NSS_NOT_TRUSTED: "CKT_NSS_NOT_TRUSTED",
        CKA_NSS_MOZILLA_CA_POLICY: "CKA_NSS_MOZILLA_CA_POLICY"
    };
    var MozillaTypes = {
        CK_BBOOL: "CK_BBOOL",
        UTF8: "UTF8",
        CK_OBJECT_CLASS: "CK_OBJECT_CLASS",
        CK_CERTIFICATE_TYPE: "CK_CERTIFICATE_TYPE",
        MULTILINE_OCTAL: "MULTILINE_OCTAL",
        CK_TRUST: "CK_TRUST"
    };
    var mozillaURL = "http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1";
    var Mozilla = /** @class */ (function () {
        function Mozilla(codeFilter) {
            if (codeFilter === void 0) { codeFilter = ["CKA_TRUST_ALL"]; }
            this.attributes = [];
            this.certTxt = null;
            this.curIndex = 0;
            for (var i in codeFilter) {
                codeFilter[i] = "CKA_TRUST_" + codeFilter[i];
            }
            this.codeFilterList = codeFilter;
        }
        Mozilla.prototype.getTrusted = function (data) {
            return this.getByTrustValue(data, MozillaAttributes.CKT_NSS_TRUSTED_DELEGATOR);
        };
        Mozilla.prototype.getDisallowed = function (data) {
            return this.getByTrustValue(data, MozillaAttributes.CKT_NSS_NOT_TRUSTED);
        };
        Mozilla.prototype.getByTrustValue = function (data, trustval) {
            // console.log("parsing started "+ this.codeFilterList);
            var tl = new tl_create.TrustedList();
            if (data) {
                this.certText = data.replace(/\r\n/g, "\n").split("\n");
            }
            else {
                var res = request('GET', mozillaURL, { 'timeout': 10000, 'retry': true, 'headers': { 'user-agent': 'nodejs' } });
                this.certText = res.body.toString().replace(/\r\n/g, "\n").split("\n");
            }
            this.findObjectDefinitionsSegment();
            this.findTrustSegment();
            this.findBeginDataSegment();
            this.findClassSegment();
            var certs = [];
            var ncc_trust = [];
            while (this.curIndex < this.certText.length) {
                var item = this.parseListItem();
                switch (item[MozillaAttributes.CKA_CLASS]) {
                    case "CKO_CERTIFICATE":
                        certs.push(item);
                        break;
                    case "CKO_NSS_TRUST":
                        ncc_trust.push(item);
                        break;
                }
                this.findClassSegment();
            }
            var c = 0;
            for (var _i = 0, certs_1 = certs; _i < certs_1.length; _i++) {
                var cert = certs_1[_i];
                // console.log(++c, cert[MozillaAttributes.CKA_LABEL]);
                var tl_cert = {
                    raw: cert[MozillaAttributes.CKA_VALUE],
                    trust: [],
                    operator: cert[MozillaAttributes.CKA_LABEL],
                    source: "Mozilla",
                    evpolicy: []
                };
                var ncc = this.findNcc(cert, ncc_trust);
                // add trust from ncc
                for (var i in ncc) {
                    var m = /^CKA_TRUST_(\w+)/.exec(i);
                    if (m && m[1] !== "STEP_UP_APPROVED" && ncc[i] === trustval)
                        tl_cert.trust.push(m[1]);
                }
                // console.log(tl_cert);
                tl.AddCertificate(tl_cert);
            }
            tl.filter(this.emptyTrustFilter);
            return tl;
        };
        Mozilla.prototype.findNcc = function (cert, nccs) {
            for (var _i = 0, nccs_1 = nccs; _i < nccs_1.length; _i++) {
                var ncc = nccs_1[_i];
                if (cert[MozillaAttributes.CKA_ISSUER] === ncc[MozillaAttributes.CKA_ISSUER]
                    && cert[MozillaAttributes.CKA_SERIAL_NUMBER] === ncc[MozillaAttributes.CKA_SERIAL_NUMBER])
                    return ncc;
            }
        };
        Mozilla.prototype.findObjectDefinitionsSegment = function () {
            this.findSegment("Certificates");
        };
        Mozilla.prototype.findTrustSegment = function () {
            this.findSegment("Trust");
        };
        Mozilla.prototype.findBeginDataSegment = function () {
            this.findSegment("BEGINDATA");
        };
        Mozilla.prototype.findClassSegment = function () {
            this.findSegment(MozillaAttributes.CKA_CLASS);
        };
        Mozilla.prototype.findSegment = function (name) {
            while (this.curIndex < this.certText.length) {
                var patt = new RegExp("(" + name + ")");
                var res = this.certText[this.curIndex].match(patt);
                if (res) {
                    return;
                }
                this.curIndex++;
            }
        };
        Mozilla.prototype.getValue = function (type, value) {
            if (value === void 0) { value = []; }
            var _value = value.join(" ");
            switch (type) {
                case MozillaTypes.CK_BBOOL:
                    return (_value === "CK_TRUE") ? true : false;
                case MozillaTypes.CK_CERTIFICATE_TYPE:
                case MozillaTypes.CK_OBJECT_CLASS:
                case MozillaTypes.CK_TRUST:
                    return _value;
                case MozillaTypes.MULTILINE_OCTAL:
                    var row = null;
                    var res = [];
                    while (row = this.certText[++this.curIndex]) {
                        if (row.match(/END/)) {
                            break;
                        }
                        var vals = row.split(/\\/g);
                        vals.shift();
                        for (var _i = 0, vals_1 = vals; _i < vals_1.length; _i++) {
                            var item = vals_1[_i];
                            res.push(parseInt(item, 8));
                        }
                    }
                    //return XAdES.Convert.ToBase64String(XAdES.Convert.FromBufferString(new Uint8Array(res)));
                    //return XAdES.Convert.ToBase64(XAdES.Convert.ToString(new Uint8Array(res)));
                    return XmlCore.Convert.ToBase64(new Uint8Array(res));
                case MozillaTypes.UTF8:
                    // remove " from begin and end of UTF8 string
                    var utf8 = _value.slice(1, _value.length - 1).replace(/\%/g, "%25").replace(/\\x/g, "%");
                    return decodeURIComponent(utf8);
                default:
                    throw new Error("Unknown Mozilla type in use '" + type + "'");
            }
        };
        Mozilla.prototype.getAttribute = function (row) {
            var attr = null;
            if (!row || row.match(/^#/))
                return null;
            var vals = row.split(" ");
            if (vals[0] in MozillaAttributes) {
                attr = {
                    name: vals[0],
                    type: vals[1],
                    value: this.getValue(vals[1], vals.slice(2))
                };
            }
            else
                throw new Error("Can not parse row " + this.curIndex + ": " + row);
            return attr;
        };
        Mozilla.prototype.parseListItem = function () {
            var cert = {};
            var attr = null;
            while (attr = this.getAttribute(this.certText[this.curIndex])) {
                cert[attr.name] = attr.value;
                this.curIndex++;
            }
            return cert;
        };
        Mozilla.prototype.emptyTrustFilter = function (item, index) {
            if (item.trust.length > 0)
                return true;
            else
                return false;
        };
        return Mozilla;
    }());
    tl_create.Mozilla = Mozilla;
})(tl_create || (tl_create = {}));
/// <reference types="xadesjs" />
/// <reference types="xml-core" />
var XmlCore = require("xml-core");
var XmlDSigJs = require("xmldsigjs");
var XAdES = require("xadesjs");
var tl_create;
(function (tl_create) {
    var euURL = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";
    var EUTL = /** @class */ (function () {
        function EUTL() {
            this.TrustServiceStatusLists = null;
        }
        EUTL.prototype.loadTSL = function (data) {
            var eutl = new tl_create.TrustServiceStatusList();
            var xml = XAdES.Parse(data, "application/xml");
            eutl.LoadXml(xml);
            return eutl;
        };
        EUTL.prototype.fetchAllTSLs = function () {
            var toProcess = [euURL];
            var processed = [];
            this.TrustServiceStatusLists = [];
            while (toProcess.length !== 0) {
                var url = toProcess.pop();
                processed.push(url);
                var res = request('GET', url, { 'timeout': 10000, 'retry': true, 'headers': { 'user-agent': 'nodejs' } });
                var eutl = this.loadTSL(res.getBody('utf8'));
                this.TrustServiceStatusLists.push(eutl);
                for (var _i = 0, _a = eutl.SchemaInformation.Pointers; _i < _a.length; _i++) {
                    var pointer = _a[_i];
                    if ((pointer.AdditionalInformation.MimeType === 'application/vnd.etsi.tsl+xml') &&
                        (processed.indexOf(pointer.Location) === -1))
                        toProcess.push(pointer.Location);
                }
            }
        };
        EUTL.prototype.getTrusted = function (data) {
            if (data) {
                this.TrustServiceStatusLists = [this.loadTSL(data)];
            }
            else {
                this.fetchAllTSLs();
            }
            var tl = new tl_create.TrustedList();
            for (var _i = 0, _a = this.TrustServiceStatusLists; _i < _a.length; _i++) {
                var TrustServiceStatusList_1 = _a[_i];
                for (var _b = 0, _c = TrustServiceStatusList_1.TrustServiceProviders; _b < _c.length; _b++) {
                    var trustServiceProvider = _c[_b];
                    for (var _d = 0, _e = trustServiceProvider.TSPServices; _d < _e.length; _d++) {
                        var tSPService = _e[_d];
                        for (var _f = 0, _g = tSPService.X509Certificates; _f < _g.length; _f++) {
                            var cert = _g[_f];
                            tl.AddCertificate({
                                raw: cert,
                                trust: [tSPService.ServiceTypeIdentifier],
                                operator: trustServiceProvider.TSPName.GetItem("en"),
                                source: "EUTL",
                                evpolicy: []
                            });
                        }
                    }
                }
            }
            return tl;
        };
        return EUTL;
    }());
    tl_create.EUTL = EUTL;
    tl_create.XmlNodeType = XmlCore.XmlNodeType;
    var XmlObject = /** @class */ (function () {
        function XmlObject() {
        }
        XmlObject.prototype.GetAttribute = function (node, name, defaultValue) {
            if (defaultValue === void 0) { defaultValue = null; }
            return node.hasAttribute(name) ? node.getAttribute(name) : defaultValue;
        };
        XmlObject.prototype.NextElementPos = function (nl, pos, name, ns, required) {
            while (pos < nl.length) {
                if (nl[pos].nodeType === tl_create.XmlNodeType.Element) {
                    if (nl[pos].localName !== name || nl[pos].namespaceURI !== ns) {
                        if (required)
                            throw new Error("Malformed element '" + name + "'");
                        else
                            return -2;
                    }
                    else
                        return pos;
                }
                else
                    pos++;
            }
            if (required)
                throw new Error("Malformed element '" + name + "'");
            return -1;
        };
        return XmlObject;
    }());
    var XmlTrustServiceStatusList = {
        ElementNames: {
            TrustServiceStatusList: "TrustServiceStatusList",
            SchemeInformation: "SchemeInformation",
            TSLVersionIdentifier: "TSLVersionIdentifier",
            TSLSequenceNumber: "TSLSequenceNumber",
            TSLType: "TSLType",
            SchemeOperatorName: "SchemeOperatorName",
            Name: "Name",
            SchemeOperatorAddress: "SchemeOperatorAddress",
            PostalAddresses: "PostalAddresses",
            PostalAddress: "PostalAddress",
            StreetAddress: "StreetAddress",
            Locality: "Locality",
            PostalCode: "PostalCode",
            CountryName: "CountryName",
            ElectronicAddress: "ElectronicAddress",
            URI: "URI",
            SchemeName: "SchemeName",
            SchemeInformationURI: "SchemeInformationURI",
            StatusDeterminationApproach: "StatusDeterminationApproach",
            SchemeTypeCommunityRules: "SchemeTypeCommunityRules",
            SchemeTerritory: "SchemeTerritory",
            PolicyOrLegalNotice: "PolicyOrLegalNotice",
            TSLLegalNotice: "TSLLegalNotice",
            HistoricalInformationPeriod: "HistoricalInformationPeriod",
            PointersToOtherTSL: "PointersToOtherTSL",
            OtherTSLPointer: "OtherTSLPointer",
            ServiceDigitalIdentities: "ServiceDigitalIdentities",
            ServiceDigitalIdentity: "ServiceDigitalIdentity",
            DigitalId: "DigitalId",
            X509Certificate: "X509Certificate",
            TSLLocation: "TSLLocation",
            AdditionalInformation: "AdditionalInformation",
            OtherInformation: "OtherInformation",
            ListIssueDateTime: "ListIssueDateTime",
            NextUpdate: "NextUpdate",
            dateTime: "dateTime",
            DistributionPoints: "DistributionPoints",
            MimeType: "MimeType",
            TrustServiceProviderList: "TrustServiceProviderList",
            TrustServiceProvider: "TrustServiceProvider",
            TSPName: "TSPName",
            TSPService: "TSPService",
            ServiceTypeIdentifier: "ServiceTypeIdentifier",
        },
        AttributeNames: {
            Id: "Id",
            TSLTag: "TSLTag"
        },
        NamespaceURI: "http://uri.etsi.org/02231/v2#"
    };
    var TrustServiceStatusList = /** @class */ (function (_super) {
        __extends(TrustServiceStatusList, _super);
        function TrustServiceStatusList() {
            var _this = _super !== null && _super.apply(this, arguments) || this;
            _this.Id = null;
            _this.TSLTag = null;
            _this.SchemaInformation = null;
            _this.TrustServiceProviders = [];
            return _this;
        }
        TrustServiceStatusList.prototype.LoadXml = function (value) {
            if (value == null)
                throw new Error("Parameter 'value' is required");
            if (value.constructor.name === "Document" || value instanceof Document)
                value = value.documentElement;
            if ((value.localName === XmlTrustServiceStatusList.ElementNames.TrustServiceStatusList) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
                // Id
                this.Id = this.GetAttribute(value, XmlTrustServiceStatusList.AttributeNames.Id);
                // TSLTag
                this.TSLTag = this.GetAttribute(value, XmlTrustServiceStatusList.AttributeNames.TSLTag);
                this.SchemaInformation = new SchemeInformation();
                var i = this.NextElementPos(value.childNodes, 0, XmlTrustServiceStatusList.ElementNames.SchemeInformation, XmlTrustServiceStatusList.NamespaceURI, true);
                this.SchemaInformation.LoadXml(value.childNodes[i]);
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.TrustServiceProviderList, XmlTrustServiceStatusList.NamespaceURI, false);
                if (i > 0) {
                    var el = value.childNodes[i];
                    var TrustServiceProviderNodes = el.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.TrustServiceProvider);
                    for (var i_1 = 0; i_1 < TrustServiceProviderNodes.length; i_1++) {
                        var TrustServiceProviderNode = TrustServiceProviderNodes[i_1];
                        var trustServiceProvider = new TrustServiceProvider();
                        trustServiceProvider.LoadXml(TrustServiceProviderNode);
                        this.TrustServiceProviders.push(trustServiceProvider);
                    }
                }
                this.m_element = value;
            }
            else
                throw new Error("Wrong XML element");
        };
        TrustServiceStatusList.prototype.CheckSignature = function () {
            var xmlSignature = this.m_element.getElementsByTagNameNS(XmlDSigJs.XmlSignature.NamespaceURI, "Signature");
            // TODO: change this.m_element.ownerDocument -> this.m_element after XAdES fix;
            var sxml = new XAdES.SignedXml(this.m_element.ownerDocument);
            sxml.LoadXml(xmlSignature[0]);
            return sxml.Verify();
        };
        return TrustServiceStatusList;
    }(XmlObject));
    tl_create.TrustServiceStatusList = TrustServiceStatusList;
    var SchemeInformation = /** @class */ (function (_super) {
        __extends(SchemeInformation, _super);
        function SchemeInformation() {
            var _this = _super !== null && _super.apply(this, arguments) || this;
            _this.Pointers = [];
            return _this;
        }
        SchemeInformation.prototype.LoadXml = function (value) {
            if (value == null)
                throw new Error("Parameter 'value' is required");
            if ((value.localName === XmlTrustServiceStatusList.ElementNames.SchemeInformation) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
                // TSLVersionIdentifier
                var i = this.NextElementPos(value.childNodes, 0, XmlTrustServiceStatusList.ElementNames.TSLVersionIdentifier, XmlTrustServiceStatusList.NamespaceURI, true);
                this.Version = +value.childNodes[i].textContent;
                // TSLSequenceNumber
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.TSLSequenceNumber, XmlTrustServiceStatusList.NamespaceURI, true);
                this.SequenceNumber = +value.childNodes[i].textContent;
                // TSLType
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.TSLType, XmlTrustServiceStatusList.NamespaceURI, true);
                this.Type = value.childNodes[i].textContent;
                // SchemeOperatorName
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.SchemeOperatorName, XmlTrustServiceStatusList.NamespaceURI, true);
                // SchemeOperatorAddress
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.SchemeOperatorAddress, XmlTrustServiceStatusList.NamespaceURI, true);
                // SchemeName
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.SchemeName, XmlTrustServiceStatusList.NamespaceURI, true);
                // SchemeInformationURI
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.SchemeInformationURI, XmlTrustServiceStatusList.NamespaceURI, true);
                // StatusDeterminationApproach
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.StatusDeterminationApproach, XmlTrustServiceStatusList.NamespaceURI, true);
                this.StatusDeterminationApproach = value.childNodes[i].textContent;
                // SchemeTypeCommunityRules
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.SchemeTypeCommunityRules, XmlTrustServiceStatusList.NamespaceURI, true);
                // SchemeTerritory
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.SchemeTerritory, XmlTrustServiceStatusList.NamespaceURI, true);
                this.StatusDeterminationApproach = value.childNodes[i].textContent;
                // PolicyOrLegalNotice
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.PolicyOrLegalNotice, XmlTrustServiceStatusList.NamespaceURI, true);
                // HistoricalInformationPeriod
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.HistoricalInformationPeriod, XmlTrustServiceStatusList.NamespaceURI, true);
                this.HistoricalInformationPeriod = +value.childNodes[i].textContent;
                // PointersToOtherTSL
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.PointersToOtherTSL, XmlTrustServiceStatusList.NamespaceURI, true);
                var pointers = value.childNodes[i].childNodes;
                for (var j = 0; j < pointers.length; j++) {
                    // OtherTSLPointer
                    var node = pointers[j];
                    if (node.nodeType !== tl_create.XmlNodeType.Element)
                        continue;
                    var pointer = new Pointer();
                    pointer.LoadXml(node);
                    this.Pointers.push(pointer);
                }
            }
            else
                throw new Error("Wrong XML element");
        };
        return SchemeInformation;
    }(XmlObject));
    var Pointer = /** @class */ (function (_super) {
        __extends(Pointer, _super);
        function Pointer() {
            var _this = _super !== null && _super.apply(this, arguments) || this;
            _this.Location = null;
            _this.X509Certificates = [];
            _this.AdditionalInformation = null;
            return _this;
        }
        Pointer.prototype.LoadXml = function (value) {
            if (value == null)
                throw new Error("Parameter 'value' is required");
            if ((value.localName === XmlTrustServiceStatusList.ElementNames.OtherTSLPointer) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
                // ServiceDigitalIdentities
                var i = this.NextElementPos(value.childNodes, 0, XmlTrustServiceStatusList.ElementNames.ServiceDigitalIdentities, XmlTrustServiceStatusList.NamespaceURI, true);
                var serviceDigitalIdentities = value.childNodes[i].childNodes;
                for (var j = 0; j < serviceDigitalIdentities.length; j++) {
                    if (serviceDigitalIdentities[j].nodeType !== tl_create.XmlNodeType.Element)
                        continue;
                    // X509Certificate
                    var elsX509 = serviceDigitalIdentities[j].getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.X509Certificate);
                    for (var k = 0; k < elsX509.length; k++)
                        this.X509Certificates.push(elsX509[k].textContent);
                }
                // TSLLocation
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.TSLLocation, XmlTrustServiceStatusList.NamespaceURI, true);
                this.Location = value.childNodes[i].textContent;
                // AdditionalInformation
                i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.AdditionalInformation, XmlTrustServiceStatusList.NamespaceURI, true);
                this.AdditionalInformation = new AdditionalInformation();
                this.AdditionalInformation.LoadXml(value.childNodes[i]);
            }
            else
                throw new Error("Wrong XML element");
        };
        return Pointer;
    }(XmlObject));
    var AdditionalInformation = /** @class */ (function (_super) {
        __extends(AdditionalInformation, _super);
        function AdditionalInformation() {
            var _this = _super !== null && _super.apply(this, arguments) || this;
            _this.TSLType = null;
            _this.SchemeTerritory = null;
            _this.SchemeOperatorName = new SchemeOperatorName();
            _this.SchemeTypeCommunityRules = [];
            _this.MimeType = null;
            return _this;
        }
        AdditionalInformation.prototype.LoadXml = function (value) {
            if (value == null)
                throw new Error("Parameter 'value' is required");
            if ((value.localName === XmlTrustServiceStatusList.ElementNames.AdditionalInformation) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
                // Search for OtherInformation
                var OtherInformationList = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.OtherInformation);
                for (var i = 0; i < OtherInformationList.length; i++) {
                    // get first element
                    var node = this.GetFirstElement(OtherInformationList[i].childNodes);
                    if (node) {
                        switch (node.localName) {
                            case XmlTrustServiceStatusList.ElementNames.SchemeTerritory:
                                this.SchemeTerritory = node.textContent;
                                break;
                            case XmlTrustServiceStatusList.ElementNames.TSLType:
                                this.TSLType = node.textContent;
                                break;
                            case XmlTrustServiceStatusList.ElementNames.SchemeOperatorName:
                                this.SchemeOperatorName.LoadXml(node);
                                break;
                            case XmlTrustServiceStatusList.ElementNames.SchemeTypeCommunityRules:
                                var elements = node.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.URI);
                                for (var j = 0; j < elements.length; j++) {
                                    this.SchemeTypeCommunityRules.push(elements[j].textContent);
                                }
                                break;
                            case XmlTrustServiceStatusList.ElementNames.MimeType:
                                this.MimeType = node.textContent;
                                break;
                        }
                    }
                }
            }
            else
                throw new Error("Wrong XML element");
        };
        AdditionalInformation.prototype.GetFirstElement = function (nl) {
            for (var i = 0; i < nl.length; i++) {
                var node = nl[i];
                if (node.nodeType !== tl_create.XmlNodeType.Element)
                    continue;
                return node;
            }
            return null;
        };
        return AdditionalInformation;
    }(XmlObject));
    var MultiLangType = /** @class */ (function (_super) {
        __extends(MultiLangType, _super);
        function MultiLangType() {
            var _this = _super !== null && _super.apply(this, arguments) || this;
            _this.m_elements = [];
            return _this;
        }
        MultiLangType.prototype.GetItem = function (lang) {
            for (var _i = 0, _a = this.m_elements; _i < _a.length; _i++) {
                var item = _a[_i];
                if (item.lang = lang)
                    return item.item;
            }
            return null;
        };
        MultiLangType.prototype.GetLang = function (el) {
            var lang = this.GetAttribute(el, "xml:lang");
            return lang || null;
        };
        MultiLangType.prototype.AddItem = function (el, lang) {
            this.m_elements.push({ item: el, lang: lang });
        };
        return MultiLangType;
    }(XmlObject));
    var SchemeOperatorName = /** @class */ (function (_super) {
        __extends(SchemeOperatorName, _super);
        function SchemeOperatorName() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        SchemeOperatorName.prototype.LoadXml = function (value) {
            if (value == null)
                throw new Error("Parameter 'value' is required");
            if ((value.localName === XmlTrustServiceStatusList.ElementNames.SchemeOperatorName) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
                // Search for OtherInformation
                var elements = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.Name);
                for (var i = 0; i < elements.length; i++) {
                    var element = elements[i];
                    var lang = this.GetLang(element);
                    if (!lang)
                        throw new Error("SchemeOperatorName:Name has no xml:lang attribute");
                    this.AddItem(element.textContent, lang);
                }
            }
            else
                throw new Error("Wrong XML element");
        };
        return SchemeOperatorName;
    }(MultiLangType));
    var TrustServiceProvider = /** @class */ (function (_super) {
        __extends(TrustServiceProvider, _super);
        function TrustServiceProvider() {
            var _this = _super !== null && _super.apply(this, arguments) || this;
            _this.TSPName = null;
            _this.TSPServices = [];
            return _this;
        }
        TrustServiceProvider.prototype.LoadXml = function (value) {
            if (value == null)
                throw new Error("Parameter 'value' is required");
            if ((value.localName === XmlTrustServiceStatusList.ElementNames.TrustServiceProvider) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
                var TSPNameNodes = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.TSPName);
                if (TSPNameNodes.length > 0) {
                    this.TSPName = new TSPName();
                    this.TSPName.LoadXml(TSPNameNodes[0]);
                }
                var TSPServiceNodes = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.TSPService);
                for (var i = 0; i < TSPServiceNodes.length; i++) {
                    var TSPServiceNode = TSPServiceNodes[i];
                    var tSPService = new TSPService();
                    tSPService.LoadXml(TSPServiceNode);
                    this.TSPServices.push(tSPService);
                }
            }
            else
                throw new Error("Wrong XML element");
        };
        return TrustServiceProvider;
    }(XmlObject));
    var TSPService = /** @class */ (function (_super) {
        __extends(TSPService, _super);
        function TSPService() {
            var _this = _super !== null && _super.apply(this, arguments) || this;
            _this.X509Certificates = [];
            _this.ServiceTypeIdentifier = null;
            return _this;
        }
        TSPService.prototype.LoadXml = function (value) {
            if (value == null)
                throw new Error("Parameter 'value' is required");
            if ((value.localName === XmlTrustServiceStatusList.ElementNames.TSPService) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
                var ServiceTypeIdentifierNodes = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.ServiceTypeIdentifier);
                if (ServiceTypeIdentifierNodes.length > 0)
                    this.ServiceTypeIdentifier = ServiceTypeIdentifierNodes[0].textContent;
                var DigitalIdNodes = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.DigitalId);
                for (var i = 0; i < DigitalIdNodes.length; i++) {
                    var DigitalId = DigitalIdNodes[i];
                    var X509CertificateNodes = DigitalId.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.X509Certificate);
                    for (var j = 0; j < X509CertificateNodes.length; j++) {
                        this.X509Certificates.push(X509CertificateNodes[j].textContent);
                    }
                }
            }
            else
                throw new Error("Wrong XML element");
        };
        return TSPService;
    }(XmlObject));
    var TSPName = /** @class */ (function (_super) {
        __extends(TSPName, _super);
        function TSPName() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        TSPName.prototype.LoadXml = function (value) {
            if (value == null)
                throw new Error("Parameter 'value' is required");
            if ((value.localName === XmlTrustServiceStatusList.ElementNames.TSPName) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
                // Search for OtherInformation
                var elements = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.Name);
                for (var i = 0; i < elements.length; i++) {
                    var element = elements[i];
                    var lang = this.GetLang(element);
                    if (!lang)
                        throw new Error("TSPName:Name has no xml:lang attribute");
                    this.AddItem(element.textContent, lang);
                }
            }
            else
                throw new Error("Wrong XML element");
        };
        return TSPName;
    }(MultiLangType));
})(tl_create || (tl_create = {}));
/// <reference path="sync-request.d.ts" />
var fs = require("fs");
var temp = require("temp");
var path = require("path");
var child_process = require("child_process");
var Asn1js = require("asn1js");
var PvUtils = require("pvutils");
var tl_create;
(function (tl_create) {
    var ctl_schema = new Asn1js.Sequence({
        name: "CTL",
        value: [
            new Asn1js.Any({
                name: "dummy1"
            }),
            new Asn1js.Integer({
                name: "unknown"
            }),
            new Asn1js.UTCTime({
                name: "GenDate"
            }),
            new Asn1js.Any({
                name: "dummy2"
            }),
            new Asn1js.Sequence({
                name: "InnerCTL",
                value: [
                    new Asn1js.Repeated({
                        name: "CTLEntry",
                        value: new Asn1js.Any()
                    })
                ]
            })
        ]
    });
    var ctlentry_schema = new Asn1js.Sequence({
        name: "CTLEntry",
        value: [
            new Asn1js.OctetString({
                name: "CertID"
            }),
            new Asn1js.Set({
                name: "MetaData",
                value: [
                    new Asn1js.Repeated({
                        name: "CertMetaData",
                        value: new Asn1js.Sequence({
                            value: [
                                new Asn1js.ObjectIdentifier({
                                    name: "MetaDataType"
                                }),
                                new Asn1js.Set({
                                    name: "MetaDataValue",
                                    value: [
                                        new Asn1js.OctetString({
                                            name: "RealContent"
                                        })
                                    ]
                                })
                            ]
                        })
                    })
                ]
            })
        ]
    });
    var eku_schema = new Asn1js.Sequence({
        name: "EKU",
        value: [
            new Asn1js.Repeated({
                name: "OID",
                value: new Asn1js.ObjectIdentifier()
            })
        ]
    });
    var evoid_schema = new Asn1js.Sequence({
        name: "EVOIDS",
        value: [
            new Asn1js.Repeated({
                name: "PolicyThing",
                value: new Asn1js.Sequence({
                    value: [
                        new Asn1js.ObjectIdentifier({
                            name: "EVOID"
                        }),
                        new Asn1js.Any({
                            name: "dummy"
                        })
                    ]
                })
            })
        ]
    });
    var dis_ctl_schema = new Asn1js.Sequence({
        name: "DisallowedCTL",
        value: [
            new Asn1js.Any({
                name: "dummy1"
            }),
            new Asn1js.OctetString({
                name: "dummy2"
            }),
            new Asn1js.Integer({
                name: "unknown"
            }),
            new Asn1js.UTCTime({
                name: "GenDate"
            }),
            new Asn1js.Any({
                name: "dummy3"
            }),
            new Asn1js.Sequence({
                name: "InnerCTL",
                value: [
                    new Asn1js.Repeated({
                        name: "CTLEntry",
                        value: new Asn1js.Any()
                    })
                ]
            })
        ]
    });
    var dis_ctlentry_schema = new Asn1js.Sequence({
        name: "DisallowedCTLEntry",
        value: [
            new Asn1js.OctetString({
                name: "CertID"
            })
        ]
    });
    var EKU_oids = {
        "1.3.6.1.5.5.7.3.1": "SERVER_AUTH",
        "1.3.6.1.5.5.7.3.2": "CLIENT_AUTH",
        "1.3.6.1.5.5.7.3.3": "CODE_SIGNING",
        "1.3.6.1.5.5.7.3.4": "EMAIL_PROTECTION",
        "1.3.6.1.5.5.7.3.5": "IPSEC_END_SYSTEM",
        "1.3.6.1.5.5.7.3.6": "IPSEC_TUNNEL",
        "1.3.6.1.5.5.7.3.7": "IPSEC_USER",
        "1.3.6.1.5.5.7.3.8": "TIME_STAMPING",
        "1.3.6.1.5.5.7.3.9": "OCSP_SIGNING",
        "1.3.6.1.5.5.8.2.2": "IPSEC_PROTECTION",
        "1.3.6.1.4.1.311.10.3.12": "DOCUMENT_SIGNING",
        "1.3.6.1.4.1.311.10.3.4": "EFS_CRYPTO"
    };
    var microsoftTrustedURL = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab";
    var microsoftTrustedFilename = "authroot.stl";
    var microsoftDisallowedURL = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab";
    var microsoftDisallowedFilename = "disallowedcert.stl";
    var Microsoft = /** @class */ (function () {
        function Microsoft() {
        }
        Microsoft.prototype.getTrusted = function (data, skipfetch) {
            if (skipfetch === void 0) { skipfetch = false; }
            var tl = new tl_create.TrustedList();
            var databuf;
            if (!data)
                databuf = this.fetchSTL(microsoftTrustedURL, microsoftTrustedFilename);
            else
                databuf = new Buffer(data, "binary");
            var variant;
            for (var i = 0; i < databuf.buffer.byteLength; i++) {
                variant = Asn1js.verifySchema(databuf.buffer.slice(i), ctl_schema);
                if (variant.verified === true)
                    break;
            }
            if (variant.verified === false)
                throw new Error("Cannot parse STL");
            if (skipfetch == false)
                process.stdout.write("Fetching certificates");
            for (var _i = 0, _a = variant.result.CTLEntry; _i < _a.length; _i++) {
                var ctlentry = _a[_i];
                if (skipfetch == false)
                    process.stdout.write(".");
                var ctlentry_parsed = Asn1js.verifySchema(ctlentry.toBER(), ctlentry_schema);
                var certid = PvUtils.bufferToHexCodes(ctlentry_parsed.result.CertID.valueBlock.valueHex);
                var certraw = "";
                if (skipfetch == false)
                    certraw = this.fetchcert(certid);
                var tl_cert = {
                    raw: certraw,
                    trust: [],
                    operator: "",
                    source: "Microsoft",
                    evpolicy: []
                };
                for (var _b = 0, _c = ctlentry_parsed.result.CertMetaData; _b < _c.length; _b++) {
                    var metadata = _c[_b];
                    var metadata_oid = metadata.valueBlock.value[0].valueBlock.toString();
                    // Load EKUs
                    if (metadata_oid === "1.3.6.1.4.1.311.10.11.9") {
                        var ekus = Asn1js.verifySchema(metadata.valueBlock.value[1].valueBlock.value[0].valueBlock.valueHex, eku_schema);
                        for (var _d = 0, _e = ekus.result.OID; _d < _e.length; _d++) {
                            var eku = _e[_d];
                            var eku_oid = eku.valueBlock.toString();
                            if (eku_oid in EKU_oids)
                                tl_cert.trust.push(EKU_oids[eku_oid]);
                        }
                    }
                    // Load friendly name
                    if (metadata_oid === "1.3.6.1.4.1.311.10.11.11") {
                        tl_cert.operator = String.fromCharCode.apply(null, new Uint16Array(metadata.valueBlock.value[1].valueBlock.value[0].valueBlock.valueHex)).slice(0, -1);
                    }
                    // Load EV Policy OIDs
                    if (metadata_oid === "1.3.6.1.4.1.311.10.11.83") {
                        var evoids = Asn1js.verifySchema(metadata.valueBlock.value[1].valueBlock.value[0].valueBlock.valueHex, evoid_schema);
                        for (var _f = 0, _g = evoids.result.PolicyThing; _f < _g.length; _f++) {
                            var evoid = _g[_f];
                            tl_cert.evpolicy.push(evoid.valueBlock.value[0].valueBlock.toString());
                        }
                    }
                }
                tl.AddCertificate(tl_cert);
            }
            if (skipfetch == false)
                console.log();
            return tl;
        };
        Microsoft.prototype.getDisallowed = function (data, skipfetch) {
            if (skipfetch === void 0) { skipfetch = false; }
            var tl = new tl_create.TrustedList();
            var databuf;
            if (!data)
                databuf = this.fetchSTL(microsoftDisallowedURL, microsoftDisallowedFilename);
            else
                databuf = new Buffer(data, "binary");
            var variant;
            for (var i = 0; i < databuf.buffer.byteLength; i++) {
                variant = Asn1js.verifySchema(databuf.buffer.slice(i), dis_ctl_schema);
                if (variant.verified === true)
                    break;
            }
            if (variant.verified === false)
                throw new Error("Cannot parse STL");
            if (skipfetch == false)
                process.stdout.write("Fetching certificates");
            for (var _i = 0, _a = variant.result.CTLEntry; _i < _a.length; _i++) {
                var ctlentry = _a[_i];
                if (skipfetch == false)
                    process.stdout.write(".");
                var ctlentry_parsed = Asn1js.verifySchema(ctlentry.toBER(), dis_ctlentry_schema);
                var certid = PvUtils.bufferToHexCodes(ctlentry_parsed.result.CertID.valueBlock.valueHex);
                var certraw = "";
                if (skipfetch == false)
                    certraw = this.fetchcert(certid);
                var tl_cert = {
                    raw: certraw,
                    trust: [],
                    operator: "Unknown",
                    source: "Microsoft",
                    evpolicy: []
                };
                tl.AddCertificate(tl_cert);
            }
            if (skipfetch == false)
                console.log();
            return tl;
        };
        Microsoft.prototype.fetchcert = function (certid) {
            var url = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/" + certid + ".crt";
            var res = request('GET', url, { 'timeout': 10000, 'retry': true, 'headers': { 'user-agent': 'nodejs' } });
            return res.body.toString('base64');
        };
        Microsoft.prototype.fetchSTL = function (uri, filename) {
            var res = request('GET', uri, { 'timeout': 10000, 'retry': true, 'headers': { 'user-agent': 'nodejs' } });
            var dirpath = temp.mkdirSync('authrootstl');
            fs.writeFileSync(path.join(dirpath, filename + '.cab'), res.body);
            if (process.platform === 'win32')
                child_process.execSync('expand ' + filename + '.cab ' + filename, { cwd: dirpath });
            else
                child_process.execSync('cabextract ' + filename + '.cab', { cwd: dirpath });
            var data = fs.readFileSync(path.join(dirpath, filename));
            fs.unlinkSync(path.join(dirpath, filename));
            fs.unlinkSync(path.join(dirpath, filename + '.cab'));
            temp.cleanupSync();
            return data;
        };
        return Microsoft;
    }());
    tl_create.Microsoft = Microsoft;
})(tl_create || (tl_create = {}));
var tl_create;
(function (tl_create) {
    var appleBaseURL = "https://opensource.apple.com/source/security_certificates/";
    var Apple = /** @class */ (function () {
        function Apple() {
        }
        Apple.prototype.getTrusted = function (datatllist, datacertlist, dataevroots, skipfetch) {
            if (skipfetch === void 0) { skipfetch = false; }
            var tl = new tl_create.TrustedList();
            var tlVersion = this.getLatestVersion(datatllist);
            var certnames = this.getTrustedCertList(tlVersion, datacertlist);
            var evroots = this.getEVOIDList(tlVersion, dataevroots);
            if (skipfetch === false)
                process.stdout.write("Fetching certificates");
            for (var _i = 0, certnames_1 = certnames; _i < certnames_1.length; _i++) {
                var certname = certnames_1[_i];
                var certraw = "";
                var evpolicies = [];
                if (skipfetch === false)
                    process.stdout.write(".");
                if (skipfetch === false)
                    certraw = this.getTrustedCert(tlVersion, certname);
                if (certname in evroots)
                    evpolicies = evroots[certname];
                var tl_cert = {
                    raw: certraw,
                    trust: ["ANY"],
                    operator: decodeURI(certname.slice(0, -4)),
                    source: "Apple",
                    evpolicy: evpolicies
                };
                tl.AddCertificate(tl_cert);
            }
            if (skipfetch === false)
                console.log();
            return tl;
        };
        Apple.prototype.getDisallowed = function (datatllist, datadiscertlist, skipfetch) {
            if (skipfetch === void 0) { skipfetch = false; }
            var tl = new tl_create.TrustedList();
            var tlVersion = this.getLatestVersion(datatllist);
            var certnames = this.getDistrustedCertList(tlVersion, datadiscertlist);
            if (skipfetch === false)
                process.stdout.write("Fetching certificates");
            for (var _i = 0, certnames_2 = certnames; _i < certnames_2.length; _i++) {
                var certname = certnames_2[_i];
                var certraw = "";
                var evpolicies = [];
                if (skipfetch === false)
                    process.stdout.write(".");
                if (skipfetch === false)
                    certraw = this.getDistrustedCert(tlVersion, certname);
                var tl_cert = {
                    raw: certraw,
                    trust: ["ANY"],
                    operator: decodeURI(certname.slice(0, -4)),
                    source: "Apple",
                    evpolicy: evpolicies
                };
                tl.AddCertificate(tl_cert);
            }
            if (skipfetch === false)
                console.log();
            return tl;
        };
        Apple.prototype.getLatestVersion = function (data) {
            if (!data) {
                var res = request("GET", appleBaseURL, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
                data = res.body.toString();
            }
            var ch = cheerio.load(data);
            var verstr;
            var vernum = -1;
            ch("td").has("img").find("a").each(function (i, anchor) {
                var href = anchor.attribs["href"];
                if (href.startsWith("security_certificates-")) {
                    var linkver = href.replace(/^security_certificates-/, "").replace(/\/*$/, "");
                    var linkarr = linkver.split(".");
                    var linknum = parseInt(linkarr[0]) * 1000000;
                    if (linkarr.length > 1)
                        linknum += parseInt(linkarr[1]) * 1000;
                    if (linkarr.length > 2)
                        linknum += parseInt(linkarr[2]);
                    if (linknum > vernum) {
                        verstr = linkver;
                        vernum = linknum;
                    }
                }
            });
            return verstr;
        };
        Apple.prototype.getTrustedCertList = function (version, data) {
            if (!data) {
                var url = appleBaseURL + "security_certificates-" + version + "/certificates/roots/";
                var res = request("GET", url, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
                data = res.body.toString();
            }
            var ch = cheerio.load(data);
            var filenames = [];
            ch("td").has("img").find("a").each(function (i, anchor) {
                var href = anchor.attribs["href"];
                if (href.endsWith("/certificates/") || href.endsWith("/../") || (href === "AppleDEVID.cer"))
                    return;
                filenames.push(href);
            });
            return filenames;
        };
        Apple.prototype.getDistrustedCertList = function (version, data) {
            if (!data) {
                var url = appleBaseURL + "security_certificates-" + version + "/certificates/distrusted/";
                var res = request("GET", url, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
                data = res.body.toString();
            }
            var ch = cheerio.load(data);
            var filenames = [];
            ch("td").has("img").find("a").each(function (i, anchor) {
                var href = anchor.attribs["href"];
                if (href.endsWith("/certificates/") || href.endsWith("/../"))
                    return;
                filenames.push(href);
            });
            return filenames;
        };
        Apple.prototype.getEVOIDList = function (version, data) {
            if (!data) {
                var url = appleBaseURL + "security_certificates-" + version + "/certificates/evroot.config?txt";
                var res = request("GET", url, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
                data = res.body.toString();
            }
            var evroots = {};
            var lines = data.split("\n").filter(function (v) { if ((v === "") || (v.indexOf("#") === 0))
                return false;
            else
                return true; });
            for (var _i = 0, lines_1 = lines; _i < lines_1.length; _i++) {
                var line = lines_1[_i];
                var linespl = this.splitLine(line);
                for (var _a = 0, _b = linespl.splice(1); _a < _b.length; _a++) {
                    var cert = _b[_a];
                    cert = cert.replace(/"/g, "");
                    if (cert in evroots)
                        evroots[cert].push(linespl[0]);
                    else
                        evroots[cert] = [linespl[0]];
                }
            }
            return evroots;
        };
        Apple.prototype.getTrustedCert = function (version, filename) {
            var url = appleBaseURL + "security_certificates-" + version + "/certificates/roots/" + filename;
            var res = request("GET", url, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
            return res.body.toString("base64");
        };
        Apple.prototype.getDistrustedCert = function (version, filename) {
            var url = appleBaseURL + "security_certificates-" + version + "/certificates/distrusted/" + filename;
            var res = request("GET", url, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
            return res.body.toString("base64");
        };
        Apple.prototype.splitLine = function (line) {
            var re_value = /(?!\s*$)\s*(?:'([^'\\]*(?:\\[\S\s][^'\\]*)*)'|"([^"\\]*(?:\\[\S\s][^"\\]*)*)"|([^ '"\s\\]*(?:\s+[^ '"\s\\]+)*))\s*(?: |$)/g;
            var a = [];
            line.replace(re_value, function (m0, m1, m2, m3) {
                if (m1 !== undefined)
                    a.push(m1.replace(/\\'/g, "'"));
                else if (m2 !== undefined)
                    a.push(m2.replace(/\\"/g, "\""));
                else if (m3 !== undefined)
                    a.push(m3);
                return "";
            });
            return a;
        };
        return Apple;
    }());
    tl_create.Apple = Apple;
})(tl_create || (tl_create = {}));
/// <reference path="sync-request.d.ts" />
var Pkijs = require("pkijs");
var Pvutils = require("pvutils");
var tl_create;
(function (tl_create) {
    var ciscoURL = "https://www.cisco.com/security/pki/trs/";
    var Cisco = /** @class */ (function () {
        function Cisco(store) {
            if (store === void 0) { store = "external"; }
            switch (store) {
                case "external":
                    this.fetchurl = ciscoURL + "ios.p7b";
                    this.source = "Cisco Trusted External Root Bundle";
                    break;
                case "union":
                    this.fetchurl = ciscoURL + "ios_union.p7b";
                    this.source = "Cisco Trusted Union Root Bundle";
                    break;
                case "core":
                    this.fetchurl = ciscoURL + "ios_core.p7b";
                    this.source = "Cisco Trusted Core Root Bundle";
                    break;
                default:
                    throw new Error("Unknown CISCO store type '" + store + "'");
            }
        }
        Cisco.prototype.getTrusted = function (data) {
            var tl = new tl_create.TrustedList();
            var databuf;
            if (!data) {
                var res = request('GET', this.fetchurl, { 'timeout': 10000, 'retry': true, 'headers': { 'user-agent': 'nodejs' } });
                databuf = res.body.buffer;
            }
            else {
                databuf = Pvutils.stringToArrayBuffer(data);
            }
            var asn1obj = Asn1js.fromBER(databuf);
            var contentInfo = new Pkijs.ContentInfo({ schema: asn1obj.result });
            if (contentInfo.contentType !== "1.2.840.113549.1.7.2")
                throw new Error("Unknown content type '" + contentInfo.contentType + "' for contentInfo");
            this.signedData = new Pkijs.SignedData({ schema: contentInfo.content });
            var asn1obj2 = Asn1js.fromBER(this.signedData.encapContentInfo.eContent.valueBlock.valueHex);
            var contentInfo2 = new Pkijs.ContentInfo({ schema: asn1obj2.result });
            if (contentInfo.contentType !== "1.2.840.113549.1.7.2")
                throw new Error("Unknown content type '" + contentInfo.contentType + "' for contentInfo");
            var signedData2 = new Pkijs.SignedData({ schema: contentInfo2.content });
            for (var _i = 0, _a = signedData2.certificates; _i < _a.length; _i++) {
                var cert = _a[_i];
                var operator = "Unknown";
                for (var _b = 0, _c = cert.subject.typesAndValues; _b < _c.length; _b++) {
                    var rdn = _c[_b];
                    if (rdn.type === "2.5.4.10") {
                        operator = rdn.value.valueBlock.value;
                        break;
                    }
                }
                tl.AddCertificate({
                    raw: Pvutils.toBase64(Pvutils.arrayBufferToString(cert.toSchema(true).toBER())),
                    trust: ["ANY"],
                    operator: operator,
                    source: this.source,
                    evpolicy: []
                });
            }
            return tl;
        };
        Cisco.prototype.getDisallowed = function (data) {
            return new tl_create.TrustedList();
        };
        Cisco.prototype.verifyP7 = function () {
            return this.signedData.verify({ signer: 0 });
        };
        return Cisco;
    }());
    tl_create.Cisco = Cisco;
})(tl_create || (tl_create = {}));
var tl_create;
(function (tl_create) {
    var TrustedList = /** @class */ (function () {
        function TrustedList() {
            this.m_certificates = [];
        }
        Object.defineProperty(TrustedList.prototype, "Certificates", {
            get: function () {
                return this.m_certificates;
            },
            enumerable: true,
            configurable: true
        });
        TrustedList.prototype.AddCertificate = function (cert) {
            cert.raw = cert.raw.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s/g, "");
            this.m_certificates.push(cert);
        };
        TrustedList.prototype.toJSON = function () {
            var res = [];
            for (var _i = 0, _a = this.Certificates; _i < _a.length; _i++) {
                var cert = _a[_i];
                res.push(cert);
            }
            return res;
        };
        TrustedList.prototype.concat = function (tl) {
            if (tl)
                this.m_certificates = this.Certificates.concat(tl.Certificates);
            return this;
        };
        TrustedList.prototype.filter = function (callbackfn, thisArg) {
            this.m_certificates = this.Certificates.filter(callbackfn);
            return this;
        };
        TrustedList.prototype.toString = function () {
            var res = [];
            for (var _i = 0, _a = this.Certificates; _i < _a.length; _i++) {
                var cert = _a[_i];
                var pem = "";
                for (var i = 0, count = 0; i < cert.raw.length; i++, count++) {
                    if (count > 63) {
                        pem = pem + "\r\n";
                        count = 0;
                    }
                    pem = pem + cert.raw[i];
                }
                res.push("Operator: " + cert.operator);
                res.push("Source: " + cert.source);
                if (cert.evpolicy.length > 0)
                    res.push("EV OIDs: " + cert.evpolicy.join(", "));
                res.push("-----BEGIN CERTIFICATE-----");
                res.push(pem);
                res.push("-----END CERTIFICATE-----");
            }
            return res.join("\n");
        };
        return TrustedList;
    }());
    tl_create.TrustedList = TrustedList;
})(tl_create || (tl_create = {}));
if (typeof module !== "undefined")
    module.exports = tl_create;
//# sourceMappingURL=tl-create.js.map