
namespace tl_create {

    const MozillaAttributes = {
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
        CKA_TRUST_STEP_UP_APPROVED: "CKA_TRUST_STEP_UP_APPROVED"
    };

    const MozillaTypes = {
        CK_BBOOL: "CK_BBOOL",
        UTF8: "UTF8",
        CK_OBJECT_CLASS: "CK_OBJECT_CLASS",
        CK_CERTIFICATE_TYPE: "CK_CERTIFICATE_TYPE",
        MULTILINE_OCTAL: "MULTILINE_OCTAL",
        CK_TRUST: "CK_TRUST"
    };

    declare type MozillaAttribute = {
        name: string;
        type: string;
        value: any;
    }

    const mozillaURL = "http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1";

    export class Mozilla {

        protected attributes: any[];
        protected certTxt: string;
        protected certText: string[];
        protected curIndex: number;
        protected codeFilterList: string[];

        constructor(codeFilter: string[] = ["CKA_TRUST_ALL"]) {
            this.attributes = [];
            this.certTxt = null;
            this.curIndex = 0;

            for (let i in codeFilter) {
                codeFilter[i] = "CKA_TRUST_" + codeFilter[i];
            }
            this.codeFilterList = codeFilter;
        }

        getTrusted(data?: string): TrustedList {
            // console.log("parsing started "+ this.codeFilterList);
            let tl = new TrustedList();

            if(data) {
                this.certText = data.replace(/\r\n/g, "\n").split("\n");
            } else {
                let res = request('GET', mozillaURL, { 'timeout': 10000, 'retry': true, 'headers': { 'user-agent': 'nodejs' } });
                this.certText = res.body.toString().replace(/\r\n/g, "\n").split("\n");
            }
            this.findObjectDefinitionsSegment();
            this.findTrustSegment();
            this.findBeginDataSegment();
            this.findClassSegment();

            let certs: any[] = [];
            let ncc_trust: any[] = [];

            while (this.curIndex < this.certText.length) {
                let item = this.parseListItem();
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

            let c = 0;
            for (let cert of certs) {
                // console.log(++c, cert[MozillaAttributes.CKA_LABEL]);
                let tl_cert: X509Certificate = {
                    raw: cert[MozillaAttributes.CKA_VALUE],
                    trust: [],
                    operator: cert[MozillaAttributes.CKA_LABEL],
                    source: "Mozilla",
                    evpolicy: []
                };
                let ncc = this.findNcc(cert, ncc_trust);
                // add trust from ncc
                for (let i in ncc) {
                    let m = /^CKA_TRUST_(\w+)/.exec(i);
                    if (m && m[1] !== "STEP_UP_APPROVED")
                        tl_cert.trust.push(m[1]);
                }
                // console.log(tl_cert);
                tl.AddCertificate(tl_cert);
            }
            return tl;
        }

        protected findNcc(cert: any, nccs: any[]) {
            for (let ncc of nccs) {
                if (cert[MozillaAttributes.CKA_ISSUER] === ncc[MozillaAttributes.CKA_ISSUER]
                    && cert[MozillaAttributes.CKA_SERIAL_NUMBER] === ncc[MozillaAttributes.CKA_SERIAL_NUMBER])
                    return ncc;
            }
        }

        protected findObjectDefinitionsSegment(): void {
            this.findSegment("Certificates");
        }

        protected findTrustSegment(): void {
            this.findSegment("Trust");
        }

        protected findBeginDataSegment(): void {
            this.findSegment("BEGINDATA");
        }

        protected findClassSegment(): void {
            this.findSegment(MozillaAttributes.CKA_CLASS);
        }

        protected findSegment(name: string) {
            while (this.curIndex < this.certText.length) {
                let patt = new RegExp(`(${name})`);
                let res = this.certText[this.curIndex].match(patt);
                if (res) {
                    return;
                }
                this.curIndex++;
            }

        }

        protected getValue(type: string, value: string[] = []): any {
            let _value = value.join(" ");
            switch (type) {
                case MozillaTypes.CK_BBOOL:
                    return (_value === "CK_TRUE") ? true : false;
                case MozillaTypes.CK_CERTIFICATE_TYPE:
                case MozillaTypes.CK_OBJECT_CLASS:
                case MozillaTypes.CK_TRUST:
                    return _value;
                case MozillaTypes.MULTILINE_OCTAL:
                    let row: string = null;
                    let res: number[] = [];
                    while (row = this.certText[++this.curIndex]) {
                        if (row.match(/END/)) {
                            break;
                        }
                        let vals = row.split(/\\/g);
                        vals.shift();
                        for (let item of vals) {
                            res.push(parseInt(item, 8));
                        }
                    }
                    return xadesjs.Convert.ToBase64String(xadesjs.Convert.FromBufferString(new Uint8Array(res)));
                case MozillaTypes.UTF8:
                    // remove " from begin and end of UTF8 string
                    let utf8 = _value.slice(1, _value.length - 1).replace(/\%/g, "%25").replace(/\\x/g, "%");
                    return decodeURIComponent(utf8);
                default:
                    throw new Error(`Unknown Mozilla type in use '${type}'`);
            }
        }

        protected getAttribute(row: string): MozillaAttribute {
            let attr: MozillaAttribute = null;
            if (!row || row.match(/^#/))
                return null;

            let vals = row.split(" ");
            if (vals[0] in MozillaAttributes) {
                attr = {
                    name: vals[0],
                    type: vals[1],
                    value: this.getValue(vals[1], vals.slice(2))
                };
            }
            else
                throw new Error(`Can not parse row ${this.curIndex}: ${row}`);

            return attr;
        }

        protected parseListItem(): any {
            let cert: any = {};
            let attr: MozillaAttribute = null;
            while (attr = this.getAttribute(this.certText[this.curIndex])) {
                cert[attr.name] = attr.value;
                this.curIndex++;
            }
            return cert;
        }
    }

}
