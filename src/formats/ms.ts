/// <reference path="asn1js.d.ts" />
/// <reference path="sync-request.d.ts" />

let fs = require("fs");
let temp = require("temp");
let path = require("path");
let child_process = require("child_process");

namespace tl_create {
    const ctl_schema = new asn1js.org.pkijs.asn1.SEQUENCE({
        name: "CTL",
        value: [
            new asn1js.org.pkijs.asn1.ANY({
                name: "dummy1"
            }),
            new asn1js.org.pkijs.asn1.INTEGER({
                name: "unknown"
            }),
            new asn1js.org.pkijs.asn1.UTCTIME({
                name: "GenDate"
            }),
            new asn1js.org.pkijs.asn1.ANY({
                name: "dummy2"
            }),
            new asn1js.org.pkijs.asn1.SEQUENCE({
                name: "InnerCTL",
                value: [
                    new asn1js.org.pkijs.asn1.REPEATED({
                        name: "CTLEntry",
                        value: new asn1js.org.pkijs.asn1.ANY()
                    })
                ]
            })
        ]
    });

    const ctlentry_schema = new asn1js.org.pkijs.asn1.SEQUENCE({
        name: "CTLEntry",
        value: [
            new asn1js.org.pkijs.asn1.OCTETSTRING({
                name: "CertID"
            }),
            new asn1js.org.pkijs.asn1.SET({
                name: "MetaData",
                value: [
                    new asn1js.org.pkijs.asn1.REPEATED({
                        name: "CertMetaData",
                        value: new asn1js.org.pkijs.asn1.SEQUENCE({
                            value: [
                                new asn1js.org.pkijs.asn1.OID({
                                    name: "MetaDataType"
                                }),
                                new asn1js.org.pkijs.asn1.SET({
                                    name: "MetaDataValue",
                                    value: [
                                        new asn1js.org.pkijs.asn1.OCTETSTRING({
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

    const eku_schema = new asn1js.org.pkijs.asn1.SEQUENCE({
        name: "EKU",
        value: [
            new asn1js.org.pkijs.asn1.REPEATED({
                name: "OID",
                value: new asn1js.org.pkijs.asn1.OID()
            })
        ]
    });

    const evoid_schema = new asn1js.org.pkijs.asn1.SEQUENCE({
        name: "EVOIDS",
        value: [
            new asn1js.org.pkijs.asn1.REPEATED({
                name: "PolicyThing",
                value: new asn1js.org.pkijs.asn1.SEQUENCE({
                    value: [
                        new asn1js.org.pkijs.asn1.OID({
                            name: "EVOID"
                        }),
                        new asn1js.org.pkijs.asn1.ANY({
                            name: "dummy"
                        })
                    ]
                })
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

    export class Microsoft {

        getTrusted(skipfetch = false): TrustedList {
            let tl = new TrustedList();

            let data = this.fetchSTL(microsoftTrustedURL, microsoftTrustedFilename);

            let variant: any;
            for(let i = 0; i < data.buffer.byteLength; i++) {
                variant = asn1js.org.pkijs.verifySchema(data.buffer.slice(i), ctl_schema);
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
                let ctlentry_parsed = asn1js.org.pkijs.verifySchema(ctlentry.toBER(), ctlentry_schema);

                let certid = asn1js.org.pkijs.bufferToHexCodes(ctlentry_parsed.result.CertID.value_block.value_hex);

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
                    let metadata_oid = metadata.value_block.value[0].value_block.toString();

                    // Load EKUs
                    if(metadata_oid === "1.3.6.1.4.1.311.10.11.9") {
                        let ekus = asn1js.org.pkijs.verifySchema(metadata.value_block.value[1].value_block.value[0].value_block.value_hex, eku_schema);
                        for(let eku of ekus.result.OID) {
                            let eku_oid = eku.value_block.toString();
                            if(eku_oid in EKU_oids)
                                tl_cert.trust.push((<any> EKU_oids)[eku_oid]);
                        }
                    }

                    // Load friendly name
                    if(metadata_oid === "1.3.6.1.4.1.311.10.11.11") {
                        tl_cert.operator = String.fromCharCode.apply(null, new Uint16Array(metadata.value_block.value[1].value_block.value[0].value_block.value_hex)).slice(0, -1);
                    }

                    // Load EV Policy OIDs
                    if(metadata_oid === "1.3.6.1.4.1.311.10.11.83") {
                        let evoids = asn1js.org.pkijs.verifySchema(metadata.value_block.value[1].value_block.value[0].value_block.value_hex, evoid_schema);
                        for(let evoid of evoids.result.PolicyThing) {
                            tl_cert.evpolicy.push(evoid.value_block.value[0].value_block.toString());
                        }
                    }
                }

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
