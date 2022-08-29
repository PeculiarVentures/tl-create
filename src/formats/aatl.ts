import * as PDFjs from "pdfjs-dist/legacy/build/pdf.js";
import * as XmlCore from "xml-core";
import * as XAdES from "xadesjs";

import { TrustedList } from "../tl";

// TODO: Add signature check
export class AATL {
  public static URL = "https://trustlist.adobe.com/tl12.acrobatsecuritysettings";

  protected url: string;

  constructor({ url = AATL.URL } = {}) {
    this.url = url;
  }

  async extractFile() {
    const doc = await PDFjs.getDocument(this.url).promise;

    const attachments = await doc.getAttachments();
    const attachmentName = "SecuritySettings.xml";
    const attachment = attachments[attachmentName];

    if (!attachment) {
      throw new Error(`Attachment ${attachmentName} not found in the source document`);
    }

    if (!attachment.content) {
      throw new Error(`Attachment ${attachmentName} content is unavailable or invalid`);
    }

    const xml = Buffer.from(attachment.content).toString("utf8");

    return xml;
  }

  async getTrusted(data?: string) {
    if (!data) {
      data = await this.extractFile();
    }

    const parsed = XAdES.Parse(data);

    if (!(XmlCore.isElement(parsed.lastChild))) {
      throw new Error("AATL: Invalid XML structure");
    }

    const settings = SecuritySettings.LoadXml(parsed.lastChild);

    let tl = new TrustedList();

    const trustItems: (keyof (typeof XmlSecuritySettings.TrustTypeMapping))[] = [
      "ROOT",
      "CERTIFIED_DOCUMENTS",
      "DYNAMIC_CONTENT",
      "JAVASCRIPT",
    ];

    for (const identity of settings.TrustedIdentities!.GetIterator()) {
      if (identity.Trust === null || identity.Certificate === null) {
        continue;
      }

      // if someway xml will contain non-AATL sourced items, skip them
      if (identity.Identification!.Source !== "AATL") {
        continue;
      }

      const trust = [];

      for (const trustName of trustItems) {
        const localName = XmlSecuritySettings.TrustTypeMapping[trustName];

        if (identity.Trust[localName] === true) {
          trust.push(trustName);
        }
      }

      const policyArray = identity.PolicyRestrictions?.CertificatePolicies?.GetIterator() || [];
      const evpolicy = policyArray.map(oid => oid.Value!);

      tl.AddCertificate({
        trust,
        evpolicy,
        // TODO: Add operator detection if reasonable
        operator: "Unknown",
        raw: identity.Certificate,
        source: "AATL"
      });
    }

    return tl;
  }

  async getDisallowed(data?: string) {
    if (!data) {
      data = await this.extractFile();
    }

    const parsed = XAdES.Parse(data);

    if (!(XmlCore.isElement(parsed.lastChild))) {
      throw new Error("AATL: Invalid XML structure");
    }

    const settings = SecuritySettings.LoadXml(parsed.lastChild);

    let tl = new TrustedList();

    for (const identity of settings.TrustedIdentities!.GetIterator()) {
      if (identity.ImportAction !== 3) {
        continue;
      }

      // if someway xml will contain non-AATL sourced items, skip them
      if (identity.Identification?.Source !== "AATL") {
        continue;
      }

      const evpolicy = identity.PolicyRestrictions?.CertificatePolicies?.GetIterator().map((oid) => oid.Value!) || [];

      tl.AddCertificate({
        trust: [],
        evpolicy,
        raw: identity.Certificate!,
        source: "AATL"
      });
    }

    return tl;
  }
}

// region XML parsing
const XmlSecuritySettings = {
  ElementNames: {
    SecuritySettings: "SecuritySettings",
    TrustedIdentities: "TrustedIdentities",
    Identity: "Identity",
    ImportAction: "ImportAction",
    Certificate: "Certificate",
    Trust: "Trust",
    Root: "Root",
    CertifiedDocuments: "CertifiedDocuments",
    DynamicContent: "DynamicContent",
    JavaScript: "JavaScript",
    SystemOperations: "SystemOperations",
    CrossDomain: "CrossDomain",
    ExternalStream: "ExternalStream",
    SilentPrint: "SilentPrint",
    WebLink: "WebLink",
    DataInjection: "DataInjection",
    ScriptInjection: "ScriptInjection",
    PolicyRestrictions: "PolicyRestrictions",
    NonExplicitProcessing: "NonExplicitProcessing",
    Description: "Description",
    CertificatePolicies: "CertificatePolicies",
    OID: "OID",
    Identification: "Identification",
    Source: "Source",
    Visible: "Visible",
  },
  TrustTypeMapping: {
    ROOT: "Root",
    CERTIFIED_DOCUMENTS: "CertifiedDocuments",
    DYNAMIC_CONTENT: "DynamicContent",
    JAVASCRIPT: "JavaScript",
  } as const
};

@XmlCore.XmlElement({ localName: XmlSecuritySettings.ElementNames.SystemOperations })
class SystemOperations extends XmlCore.XmlObject {
  @uniqueFlag(XmlSecuritySettings.ElementNames.CrossDomain)
  CrossDomain: boolean | null = null;

  @uniqueFlag(XmlSecuritySettings.ElementNames.ExternalStream)
  ExternalStream: boolean | null = null;

  @uniqueFlag(XmlSecuritySettings.ElementNames.SilentPrint)
  SilentPrint: boolean | null = null;

  @uniqueFlag(XmlSecuritySettings.ElementNames.WebLink)
  WebLink: boolean | null = null;

  @uniqueFlag(XmlSecuritySettings.ElementNames.DataInjection)
  DataInjection: boolean | null = null;

  @uniqueFlag(XmlSecuritySettings.ElementNames.ScriptInjection)
  ScriptInjection: boolean | null = null;
}

@XmlCore.XmlElement({ localName: XmlSecuritySettings.ElementNames.Trust })
class Trust extends XmlCore.XmlObject {
  @uniqueFlag(XmlSecuritySettings.ElementNames.Root)
  Root: boolean | null = null;

  @uniqueFlag(XmlSecuritySettings.ElementNames.CertifiedDocuments)
  CertifiedDocuments: boolean | null = null;

  @uniqueFlag(XmlSecuritySettings.ElementNames.DynamicContent)
  DynamicContent: boolean | null = null;

  @uniqueFlag(XmlSecuritySettings.ElementNames.JavaScript)
  JavaScript: boolean | null = null;

  @XmlCore.XmlChildElement({
    localName: XmlSecuritySettings.ElementNames.SystemOperations,
    maxOccurs: 1,
    parser: SystemOperations
  })
  SystemOperations: SystemOperations | null = null;
}

function uniqueFlag(name: string) {
  return XmlCore.XmlChildElement({
    localName: name,
    maxOccurs: 1,
    converter: {
      get: (value) => {
        if (value) {
          return "1";
        }
        return "0";
      },
      set: (value) => {
        switch (value) {
          case "1":
            return true;
          case "0":
            return false;
          default:
            console.warn(`AATL: WARNING, invalid value for binary flag ${name}: "${value}"`);
            return false;
        }
      },
    }
  });
}

@XmlCore.XmlElement({ localName: XmlSecuritySettings.ElementNames.OID })
class OID extends XmlCore.XmlObject {
  @XmlCore.XmlContent({ required: true })
  Value: string | null = null;
}

@XmlCore.XmlElement({ localName: XmlSecuritySettings.ElementNames.CertificatePolicies, parser: OID })
class CertificatePolicies extends XmlCore.XmlCollection<OID> { }

@XmlCore.XmlElement({ localName: XmlSecuritySettings.ElementNames.PolicyRestrictions })
class PolicyRestrictions extends XmlCore.XmlObject {
  @uniqueFlag(XmlSecuritySettings.ElementNames.NonExplicitProcessing)
  NonExplicitProcessing: boolean | null = null;

  @XmlCore.XmlChildElement({ localName: XmlSecuritySettings.ElementNames.Description, maxOccurs: 1 })
  Description: string | null = null;

  @XmlCore.XmlChildElement({ localName: XmlSecuritySettings.ElementNames.CertificatePolicies, maxOccurs: 1, parser: CertificatePolicies })
  CertificatePolicies: CertificatePolicies | null = null;
}

@XmlCore.XmlElement({ localName: XmlSecuritySettings.ElementNames.Identification })
class Identification extends XmlCore.XmlObject {
  @XmlCore.XmlChildElement({ localName: XmlSecuritySettings.ElementNames.Source, maxOccurs: 1 })
  Source: string | null = null;

  @uniqueFlag(XmlSecuritySettings.ElementNames.Visible)
  Visible: string | null = null;
}

@XmlCore.XmlElement({ localName: XmlSecuritySettings.ElementNames.Identity })
class Identity extends XmlCore.XmlObject {
  @XmlCore.XmlChildElement({
    localName: XmlSecuritySettings.ElementNames.ImportAction,
    maxOccurs: 1,
    converter: XmlCore.XmlNumberConverter,
  })
  public ImportAction: number | null = null;

  @XmlCore.XmlChildElement({
    localName: XmlSecuritySettings.ElementNames.Certificate,
    maxOccurs: 1,
  })
  public Certificate: string | null = null;

  @XmlCore.XmlChildElement({
    localName: XmlSecuritySettings.ElementNames.Trust,
    maxOccurs: 1,
    parser: Trust,
  })
  public Trust: Trust | null = null;

  @XmlCore.XmlChildElement({
    localName: XmlSecuritySettings.ElementNames.PolicyRestrictions,
    maxOccurs: 1,
    parser: PolicyRestrictions,
  })
  PolicyRestrictions: PolicyRestrictions | null = null;

  @XmlCore.XmlChildElement({
    localName: XmlSecuritySettings.ElementNames.Identification,
    maxOccurs: 1,
    parser: Identification,
  })
  Identification: Identification | null = null;
}

@XmlCore.XmlElement({ localName: XmlSecuritySettings.ElementNames.TrustedIdentities, parser: Identity })
class TrustedIdentities extends XmlCore.XmlCollection<Identity> { }

@XmlCore.XmlElement({ localName: XmlSecuritySettings.ElementNames.SecuritySettings })
class SecuritySettings extends XmlCore.XmlObject {
  @XmlCore.XmlChildElement({
    parser: TrustedIdentities,
    required: true,
  })
  public TrustedIdentities: TrustedIdentities | null = null;
}

// endregion XML parsing
