/// <reference path="sync-request.d.ts" />

let fs = require("fs");
let temp = require("temp");
let path = require("path");
let child_process = require("child_process");
let Asn1js = require("asn1js");
let PvUtils = require("pvutils");

namespace tl_create {
    const ctl_schema = new Asn1js.Sequence({
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

    const ctlentry_schema = new Asn1js.Sequence({
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

    const eku_schema = new Asn1js.Sequence({
        name: "EKU",
        value: [
            new Asn1js.Repeated({
                name: "OID",
                value: new Asn1js.ObjectIdentifier()
            })
        ]
    });

    const evoid_schema = new Asn1js.Sequence({
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

    const dis_ctl_schema = new Asn1js.Sequence({
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

    const dis_ctlentry_schema = new Asn1js.Sequence({
        name: "DisallowedCTLEntry",
        value: [
            new Asn1js.OctetString({
                name: "CertID"
            })
        ]
    });

    const EKU_oids = {
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

    const microsoftTrustedURL = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab";
    const microsoftTrustedFilename = "authroot.stl";
    const microsoftDisallowedURL = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab";
    const microsoftDisallowedFilename = "disallowedcert.stl";

    export class Microsoft {

        getTrusted(data?: string, skipfetch = false): TrustedList {
            let tl = new TrustedList();
            let databuf: Buffer;

            if(!data)
                databuf = this.fetchSTL(microsoftTrustedURL, microsoftTrustedFilename);
            else
                databuf = new Buffer(data, "binary");

            let variant: any;
            for(let i = 0; i < databuf.buffer.byteLength; i++) {
                variant = Asn1js.verifySchema(databuf.buffer.slice(i), ctl_schema);
                if(variant.verified === true)
                    break;
            }

            if(variant.verified === false)
                throw new Error("Cannot parse STL");

            if(skipfetch == false)
                process.stdout.write("Fetching certificates");
            for(let ctlentry of variant.result.CTLEntry) {
                if(skipfetch == false)
                    process.stdout.write(".");
                let ctlentry_parsed = Asn1js.verifySchema(ctlentry.toBER(), ctlentry_schema);

                let certid = PvUtils.bufferToHexCodes(ctlentry_parsed.result.CertID.valueBlock.valueHex);

                let certraw = "";
                if(skipfetch == false)
                    certraw = this.fetchcert(certid);
                let tl_cert: X509Certificate = {
                    raw: certraw,
                    trust: [],
                    operator: "",
                    source: "Microsoft",
                    evpolicy: []
                };

                for(let metadata of ctlentry_parsed.result.CertMetaData) {
                    let metadata_oid = metadata.valueBlock.value[0].valueBlock.toString();

                    // Load EKUs
                    if(metadata_oid === "1.3.6.1.4.1.311.10.11.9") {
                        let ekus = Asn1js.verifySchema(metadata.valueBlock.value[1].valueBlock.value[0].valueBlock.valueHex, eku_schema);
                        for(let eku of ekus.result.OID) {
                            let eku_oid = eku.valueBlock.toString();
                            if(eku_oid in EKU_oids)
                                tl_cert.trust.push((<any> EKU_oids)[eku_oid]);
                        }
                    }

                    // Load friendly name
                    if(metadata_oid === "1.3.6.1.4.1.311.10.11.11") {
                        tl_cert.operator = String.fromCharCode.apply(null, new Uint16Array(metadata.valueBlock.value[1].valueBlock.value[0].valueBlock.valueHex)).slice(0, -1);
                    }

                    // Load EV Policy OIDs
                    if(metadata_oid === "1.3.6.1.4.1.311.10.11.83") {
                        let evoids = Asn1js.verifySchema(metadata.valueBlock.value[1].valueBlock.value[0].valueBlock.valueHex, evoid_schema);
                        for(let evoid of evoids.result.PolicyThing) {
                            tl_cert.evpolicy.push(evoid.valueBlock.value[0].valueBlock.toString());
                        }
                    }
                }

                tl.AddCertificate(tl_cert);
            }
            if(skipfetch == false)
                console.log();

            return tl;
        }

        getDisallowed(data?: string, skipfetch = false): TrustedList {
            let tl = new TrustedList();
            let databuf: Buffer;

            if(!data)
                databuf = this.fetchSTL(microsoftDisallowedURL, microsoftDisallowedFilename);
            else
                databuf = new Buffer(data, "binary");

            let variant: any;
            for(let i = 0; i < databuf.buffer.byteLength; i++) {
                variant = Asn1js.verifySchema(databuf.buffer.slice(i), dis_ctl_schema);
                if(variant.verified === true)
                    break;
            }

            if(variant.verified === false)
                throw new Error("Cannot parse STL");

            if(skipfetch == false)
                process.stdout.write("Fetching certificates");
            for(let ctlentry of variant.result.CTLEntry) {
                if(skipfetch == false)
                    process.stdout.write(".");

                let ctlentry_parsed = Asn1js.verifySchema(ctlentry.toBER(), dis_ctlentry_schema);

                let certid = PvUtils.bufferToHexCodes(ctlentry_parsed.result.CertID.valueBlock.valueHex);

                let certraw = "";
                if(skipfetch == false)
                    certraw = this.fetchcert(certid);
                let tl_cert: X509Certificate = {
                    raw: certraw,
                    trust: [],
                    operator: "Unknown",
                    source: "Microsoft",
                    evpolicy: []
                };
                tl.AddCertificate(tl_cert);
            }
            if(skipfetch == false)
                console.log();

            return tl;
        }

        fetchcert(certid: string): string {
            let url = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/" + certid + ".crt";
            let res = request('GET', url, { 'timeout': 10000, 'retry': true, 'headers': { 'user-agent': 'nodejs' } });
            return res.body.toString('base64');
        }

        fetchSTL(uri: string, filename: string): Buffer {
            let res = request('GET', uri, { 'timeout': 10000, 'retry': true, 'headers': { 'user-agent': 'nodejs' } });

            let dirpath = temp.mkdirSync('authrootstl');
            fs.writeFileSync(path.join(dirpath, filename + '.cab'), res.body);

            if(process.platform === 'win32')
                child_process.execSync('expand ' + filename + '.cab .', { cwd: dirpath });
            else
                child_process.execSync('cabextract ' + filename + '.cab', { cwd: dirpath });

            let data = fs.readFileSync(path.join(dirpath, filename));

            fs.unlinkSync(path.join(dirpath, filename));
            fs.unlinkSync(path.join(dirpath, filename + '.cab'));

            temp.cleanupSync();

            return data;
        }

    }

}
