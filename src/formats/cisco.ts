import * as pvutils from "pvutils";
import request from "sync-request";
import { TrustedList } from "../tl";
import {asn1js, pkijs} from "../crypto";

export interface CiscoParameters {
  url?: string;
  timeout?: number;
}

export class Cisco {

  public static URL = "https://www.cisco.com/security/pki/trs/";
  public static TIMEOUT = 1e4;

  public url: string;
  public timeout: number;
  public fetchurl: string;
  public source: string;
  public signedData: any;

  constructor(store: string = "external", {
    url = Cisco.URL,
    timeout = Cisco.TIMEOUT,
  }: CiscoParameters = {}) {
    this.url = url;
    this.timeout = timeout;

    switch (store) {
      case "external":
        this.fetchurl = this.url + "ios.p7b";
        this.source = "Cisco Trusted External Root Bundle";
        break;
      case "union":
        this.fetchurl = this.url + "ios_union.p7b";
        this.source = "Cisco Trusted Union Root Bundle";
        break;
      case "core":
        this.fetchurl = this.url + "ios_core.p7b";
        this.source = "Cisco Trusted Core Root Bundle";
        break;
      default:
        throw new Error(`Unknown CISCO store type '${store}'`);
    }
  }

  getTrusted(data?: string): TrustedList {
    let tl = new TrustedList();
    let dataBuf: ArrayBuffer;

    if (!data) {
      let res = request("GET", this.fetchurl, { "timeout": this.timeout, "retry": true, "headers": { "user-agent": "nodejs" } });
      dataBuf = Buffer.isBuffer(res.body)
        ? new Uint8Array(res.body).buffer
        : new Uint8Array(Buffer.from(res.body)).buffer;
    } else {
      dataBuf = pvutils.stringToArrayBuffer(data);
    }

    const asn1obj = asn1js.fromBER(dataBuf);
    const contentInfo = new pkijs.ContentInfo({ schema: asn1obj.result });

    if (contentInfo.contentType !== "1.2.840.113549.1.7.2")
      throw new Error(`Unknown content type '${contentInfo.contentType}' for contentInfo`);

    this.signedData = new pkijs.SignedData({ schema: contentInfo.content });
    let asn1obj2 = asn1js.fromBER(this.signedData.encapContentInfo.eContent.valueBlock.valueHex);
    let contentInfo2 = new pkijs.ContentInfo({ schema: asn1obj2.result });

    if (contentInfo.contentType !== "1.2.840.113549.1.7.2")
      throw new Error(`Unknown content type '${contentInfo.contentType}' for contentInfo`);

    let signedData2 = new pkijs.SignedData({ schema: contentInfo2.content });

    for (let cert of signedData2.certificates) {
      let operator = "Unknown";
      for (let rdn of cert.subject.typesAndValues) {
        if (rdn.type === "2.5.4.10") {
          operator = rdn.value.valueBlock.value;
          break;
        }
      }
      tl.AddCertificate({
        raw: pvutils.toBase64(pvutils.arrayBufferToString(cert.toSchema(true).toBER())),
        trust: ["ANY"],
        operator: operator,
        source: this.source,
        evpolicy: []
      });
    }

    return tl;
  }

  getDisallowed(data?: string): TrustedList {
    return new TrustedList();
  }

  async verifyP7() {
    return this.signedData.verify({ signer: 0 });
  }
}
