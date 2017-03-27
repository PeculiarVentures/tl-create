/// <reference path="sync-request.d.ts" />

let Pkijs = require("pkijs");
let Pvutils = require("pvutils");

namespace tl_create {
    const ciscoURL = "https://www.cisco.com/security/pki/trs/";

    export class Cisco {
        fetchurl: string;
        source:string;

        constructor(store: string = "external") {
            switch(store) {
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
                    throw new Error(`Unknown CISCO store type '${store}'`);
            }
        }

        getTrusted(data?: string, skipfetch = false): TrustedList {
            let tl = new TrustedList();
            let databuf: Buffer;

            if(!data) {
                let res = request('GET', this.fetchurl, { 'timeout': 10000, 'retry': true, 'headers': { 'user-agent': 'nodejs' } });
                databuf = res.body.buffer;
            } else {
                databuf = new Buffer(data, "binary");
            }

            let asn1obj = Asn1js.fromBER(databuf);
            let contentInfo = new Pkijs.ContentInfo({schema: asn1obj.result});

            if(contentInfo.contentType !== "1.2.840.113549.1.7.2")
                throw new Error(`Unknown content type '${contentInfo.contentType}' for contentInfo`);

            let signedData = new Pkijs.SignedData({schema: contentInfo.content});
            let asn1obj2 = Asn1js.fromBER(signedData.encapContentInfo.eContent.valueBlock.valueHex);
            let contentInfo2 = new Pkijs.ContentInfo({schema: asn1obj2.result});

            if(contentInfo.contentType !== "1.2.840.113549.1.7.2")
                throw new Error(`Unknown content type '${contentInfo.contentType}' for contentInfo`);

            let signedData2 = new Pkijs.SignedData({schema: contentInfo2.content});

            for(let cert of signedData2.certificates) {
                let operator = "Unknown";
                for(let rdn of cert.subject.typesAndValues) {
                    if(rdn.type === "2.5.4.10") {
                        operator = rdn.value.valueBlock.value;
                        break;
                    }
                }
                tl.AddCertificate({
                    raw: Pvutils.toBase64(Pvutils.arrayBufferToString(cert.toSchema(true).toBER())),
                    trust: [ "ANY" ],
                    operator: operator,
                    source: this.source,
                    evpolicy: []
                });
            }

            return tl;
        }

        getDisallowed(data?: string, skipfetch = false): TrustedList {
            return new TrustedList();
        }
    }
}
