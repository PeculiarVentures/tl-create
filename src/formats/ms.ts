import * as pvutils from "pvutils";
import request from "sync-request";
import type { AsnSchemaType } from "asn1js";
import { asn1js } from "../crypto";
import { TrustedList, X509Certificate } from "../tl";

interface MicrosoftSchemaVariant<T = any> {
  verified: boolean;
  result: T;
}

function verifyMicrosoftSchema<T = any>(inputBuffer: ArrayBuffer, inputSchema: AsnSchemaType): MicrosoftSchemaVariant<T> {
  return asn1js.verifySchema(inputBuffer, inputSchema) as MicrosoftSchemaVariant<T>;
}

function metadataValueHex(metadata: any): ArrayBuffer {
  return metadata.valueBlock.value[1].valueBlock.value[0].valueBlock.valueHex;
}

const ctl_schema = new asn1js.Sequence({
  name: "CTL",
  value: [
    new asn1js.Any({
      name: "dummy1"
    }),
    new asn1js.Integer({
      name: "unknown"
    }),
    new asn1js.UTCTime({
      name: "GenDate"
    }),
    new asn1js.Any({
      name: "dummy2"
    }),
    new asn1js.Sequence({
      name: "InnerCTL",
      value: [
        new asn1js.Repeated({
          name: "CTLEntry",
          value: new asn1js.Any()
        })
      ]
    })
  ]
});

const ctlentry_schema = new asn1js.Sequence({
  name: "CTLEntry",
  value: [
    new asn1js.OctetString({
      name: "CertID"
    }),
    new asn1js.Set({
      name: "MetaData",
      value: [
        new asn1js.Repeated({
          name: "CertMetaData",
          value: new asn1js.Sequence({
            value: [
              new asn1js.ObjectIdentifier({
                name: "MetaDataType"
              }),
              new asn1js.Set({
                name: "MetaDataValue",
                value: [
                  new asn1js.OctetString({
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

const eku_schema = new asn1js.Sequence({
  name: "EKU",
  value: [
    new asn1js.Repeated({
      name: "OID",
      value: new asn1js.ObjectIdentifier()
    })
  ]
});

const evoid_schema = new asn1js.Sequence({
  name: "EVOIDS",
  value: [
    new asn1js.Repeated({
      name: "PolicyThing",
      value: new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({
            name: "EVOID"
          }),
          new asn1js.Any({
            name: "dummy"
          })
        ]
      })
    })
  ]
});

const dis_ctl_schema = new asn1js.Sequence({
  name: "DisallowedCTL",
  value: [
    new asn1js.Any({
      name: "dummy1"
    }),
    new asn1js.OctetString({
      name: "dummy2"
    }),
    new asn1js.Integer({
      name: "unknown"
    }),
    new asn1js.UTCTime({
      name: "GenDate"
    }),
    new asn1js.Any({
      name: "dummy3"
    }),
    new asn1js.Sequence({
      name: "InnerCTL",
      value: [
        new asn1js.Repeated({
          name: "CTLEntry",
          value: new asn1js.Any()
        })
      ]
    })
  ]
});

const dis_ctlentry_schema = new asn1js.Sequence({
  name: "DisallowedCTLEntry",
  value: [
    new asn1js.OctetString({
      name: "CertID"
    })
  ]
});

const EKU_oids: Record<string, string> = {
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

const microsoftTrustedURL = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authroot.stl";
const microsoftDisallowedURL = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcert.stl";

export class Microsoft {

  getTrusted(data?: string, skipFetch = false): TrustedList {
    let tl = new TrustedList();
    let databuf: Buffer;

    if (!data)
      databuf = this.fetchSTL(microsoftTrustedURL);
    else
      databuf = Buffer.from(data, "binary");

    let variant = this.findASN1Structure(databuf, ctl_schema);

    if (variant.verified === false)
      throw new Error("Cannot parse STL");

    if (!skipFetch)
      process.stdout.write("Fetching certificates");
    for (let ctlentry of variant.result.CTLEntry) {
      if (!skipFetch)
        process.stdout.write(".");
      let ctlentry_parsed = verifyMicrosoftSchema(ctlentry.toBER(), ctlentry_schema);
      let certid = pvutils.bufferToHexCodes(ctlentry_parsed.result.CertID.valueBlock.valueHex);

      let certraw = "";
      if (!skipFetch)
        certraw = this.fetchcert(certid);
      let tl_cert: X509Certificate = {
        raw: certraw,
        trust: [],
        operator: "",
        source: "Microsoft",
        evpolicy: []
      };

      for (let metadata of ctlentry_parsed.result.CertMetaData) {
        let metadata_oid = metadata.valueBlock.value[0].valueBlock.toString();

        // Load EKUs
        if (metadata_oid === "1.3.6.1.4.1.311.10.11.9") {
          let ekus = verifyMicrosoftSchema(metadataValueHex(metadata), eku_schema);
          for (let eku of ekus.result.OID) {
            let eku_oid = eku.valueBlock.toString();
            if (eku_oid in EKU_oids)
              tl_cert.trust?.push(EKU_oids[eku_oid]);
          }
        }

        // Load friendly name
        if (metadata_oid === "1.3.6.1.4.1.311.10.11.11") {
          tl_cert.operator = String.fromCharCode(...Array.from(new Uint16Array(metadataValueHex(metadata)))).slice(0, -1);
        }

        // Load EV Policy OIDs
        if (metadata_oid === "1.3.6.1.4.1.311.10.11.83") {
          let evoids = verifyMicrosoftSchema(metadataValueHex(metadata), evoid_schema);
          for (let evoid of evoids.result.PolicyThing) {
            tl_cert.evpolicy?.push(evoid.valueBlock.value[0].valueBlock.toString());
          }
        }
      }

      tl.AddCertificate(tl_cert);
    }
    if (!skipFetch)
      console.log();

    return tl;
  }

  getDisallowed(data?: string, skipFetch = false): TrustedList {
    let tl = new TrustedList();
    let databuf: Buffer;

    if (!data)
      databuf = this.fetchSTL(microsoftDisallowedURL);
    else
      databuf = Buffer.from(data, "binary");

    let variant = this.findASN1Structure(databuf, dis_ctl_schema);

    if (variant.verified === false)
      throw new Error("Cannot parse STL");

    if (!skipFetch)
      process.stdout.write("Fetching certificates");
    for (let ctlentry of variant.result.CTLEntry) {
      if (!skipFetch)
        process.stdout.write(".");

      let ctlentry_parsed = verifyMicrosoftSchema(ctlentry.toBER(), dis_ctlentry_schema);

      let certid = pvutils.bufferToHexCodes(ctlentry_parsed.result.CertID.valueBlock.valueHex);

      let certraw = "";
      if (!skipFetch)
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
    if (!skipFetch)
      console.log();

    return tl;
  }

  private findASN1Structure(databuf: Buffer, schema: AsnSchemaType): MicrosoftSchemaVariant {
    let variant: MicrosoftSchemaVariant = { verified: false, result: {} };
    const arrayBuffer = databuf.buffer.slice(databuf.byteOffset, databuf.byteOffset + databuf.byteLength) as ArrayBuffer;
    for (let i = 0; i < arrayBuffer.byteLength; i++) {
      try {
        variant = verifyMicrosoftSchema(arrayBuffer.slice(i), schema);
        if (variant.verified === true)
          break;
      } catch (e: unknown) {
        // Continue searching
      }
    }
    return variant;
  }

  fetchcert(certid: string): string {
    let url = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/" + certid + ".crt";
    let res = request("GET", url, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
    return res.body.toString("base64");
  }

  fetchSTL(uri: string): Buffer {
    let res = request("GET", uri, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
    return Buffer.from(res.body);
  }

}
