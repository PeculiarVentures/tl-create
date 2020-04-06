import * as XmlCore from "xml-core";
import * as XmlDSigJs from "xmldsigjs";
import * as XAdES from "xadesjs";
import request from "sync-request";
import { TrustedList } from "../tl";
import { crypto } from "../crypto";

XAdES.Application.setEngine("@peculiar/webcrypto", crypto);

const euURL = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";

export class EUTL {

  public TrustServiceStatusLists: TrustServiceStatusList[] = [];

  loadTSL(data: string): TrustServiceStatusList {
    let eutl = new TrustServiceStatusList();
    let xml = XAdES.Parse(data);

    eutl.LoadXml(xml);

    return eutl;
  }

  fetchAllTSLs(): void {
    let toProcess: string[] = [euURL];
    let processed: string[] = [];

    this.TrustServiceStatusLists = [];

    while (toProcess.length !== 0) {
      let url = toProcess.pop()!;
      processed.push(url);

      let res: any;
      let tlsBody: any;

      try {
        res = request("GET", url, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
        tlsBody = res.getBody("utf8");
      }
      catch (ex) {
        continue;
      }

      let eutl = this.loadTSL(tlsBody);

      this.TrustServiceStatusLists.push(eutl);

      for (let pointer of eutl.SchemaInformation.Pointers) {
        if ((pointer.AdditionalInformation?.MimeType === "application/vnd.etsi.tsl+xml") &&
          (processed.indexOf(pointer.Location!) === -1))
          toProcess.push(pointer.Location!);
      }
    }
  }

  getTrusted(data?: string): TrustedList {
    if (data) {
      this.TrustServiceStatusLists = [this.loadTSL(data)];
    } else {
      this.fetchAllTSLs();
    }

    let tl = new TrustedList();
    for (let TrustServiceStatusList of this.TrustServiceStatusLists) {
      for (let trustServiceProvider of TrustServiceStatusList.TrustServiceProviders) {
        for (let tSPService of trustServiceProvider.TSPServices) {
          for (let cert of tSPService.X509Certificates) {
            tl.AddCertificate({
              raw: cert,
              trust: [tSPService.ServiceTypeIdentifier!],
              operator: trustServiceProvider.TSPName?.GetItem("en")!,
              source: "EUTL",
              evpolicy: []
            });
          }
        }
      }
    }

    return tl;
  }
}

export let XmlNodeType = XmlCore.XmlNodeType;

abstract class XmlObject {

  protected GetAttribute(node: Element, name: string, defaultValue: string | null = null): string | null {
    return node.hasAttribute(name) ? node.getAttribute(name) : defaultValue;
  }

  protected NextElementPos(nl: NodeList, pos: number, name: string, ns: string, required: boolean): number {
    while (pos < nl.length) {
      const node = nl[pos];
      if (XmlCore.isElement(node)) {
        if (node.localName !== name || node.namespaceURI !== ns) {
          if (required)
            throw new Error(`Malformed element '${name}'`);
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
      throw new Error(`Malformed element '${name}'`);
    return -1;
  }
}

let XmlTrustServiceStatusList = {
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

export class TrustServiceStatusList extends XmlObject {

  #element: Element | null = null;

  public Id: string | null = null;
  public TSLTag: string | null = null;
  public SchemaInformation!: SchemeInformation;
  public TrustServiceProviders: TrustServiceProvider[] = [];

  LoadXml(value: Node): void {
    if (value == null)
      throw new Error("Parameter 'value' is required");

    if (XmlCore.isDocument(value))
      value = value.documentElement;

    if (!XmlCore.isElement(value)) {
      throw new Error(`Argument 'value' must be XML Element`);
    }

    if ((value.localName === XmlTrustServiceStatusList.ElementNames.TrustServiceStatusList) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
      // Id
      this.Id = this.GetAttribute(value as Element, XmlTrustServiceStatusList.AttributeNames.Id);
      // TSLTag
      this.TSLTag = this.GetAttribute(value as Element, XmlTrustServiceStatusList.AttributeNames.TSLTag);

      this.SchemaInformation = new SchemeInformation();

      let i = this.NextElementPos(value.childNodes, 0, XmlTrustServiceStatusList.ElementNames.SchemeInformation, XmlTrustServiceStatusList.NamespaceURI, true);
      this.SchemaInformation.LoadXml(value.childNodes[i] as Element);

      i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.TrustServiceProviderList, XmlTrustServiceStatusList.NamespaceURI, false);
      if (i > 0) {
        let el = value.childNodes[i] as Element;
        let TrustServiceProviderNodes = el.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.TrustServiceProvider);
        for (let i = 0; i < TrustServiceProviderNodes.length; i++) {
          let TrustServiceProviderNode = TrustServiceProviderNodes[i];
          let trustServiceProvider = new TrustServiceProvider();
          trustServiceProvider.LoadXml(TrustServiceProviderNode);
          this.TrustServiceProviders.push(trustServiceProvider);
        }
      }

      this.#element = value;
    }
    else
      throw new Error("Wrong XML element");
  }

  CheckSignature(): Promise<boolean> {
    if (!this.#element) {
      throw new Error("Null reference exception. Property '#element' is null");
    }

    let xmlSignature = this.#element.getElementsByTagNameNS(XmlDSigJs.XmlSignature.NamespaceURI, "Signature");

    // TODO: change this.m_element.ownerDocument -> this.m_element after XAdES fix;
    let sxml = new XAdES.SignedXml(this.#element.ownerDocument!);
    sxml.LoadXml(xmlSignature[0]);
    return sxml.Verify();
  }

}

class SchemeInformation extends XmlObject {

  public Version: number = 0;
  public SequenceNumber: number = 0;
  public Type: string = "";
  public StatusDeterminationApproach: string = "";
  public SchemeTerritory: string = "";
  public HistoricalInformationPeriod: number = 0;
  public Pointers: Pointer[] = [];

  LoadXml(value: Element): void {
    if (value == null)
      throw new Error("Parameter 'value' is required");

    if ((value.localName === XmlTrustServiceStatusList.ElementNames.SchemeInformation) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {

      // TSLVersionIdentifier
      let i = this.NextElementPos(value.childNodes, 0, XmlTrustServiceStatusList.ElementNames.TSLVersionIdentifier, XmlTrustServiceStatusList.NamespaceURI, true);
      this.Version = +(value.childNodes[i].textContent ?? 0);

      // TSLSequenceNumber
      i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.TSLSequenceNumber, XmlTrustServiceStatusList.NamespaceURI, true);
      this.SequenceNumber = +(value.childNodes[i].textContent ?? 0);

      // TSLType
      i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.TSLType, XmlTrustServiceStatusList.NamespaceURI, true);
      this.Type = value.childNodes[i].textContent!;

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
      this.StatusDeterminationApproach = value.childNodes[i].textContent!;

      // SchemeTypeCommunityRules
      i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.SchemeTypeCommunityRules, XmlTrustServiceStatusList.NamespaceURI, true);

      // SchemeTerritory
      i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.SchemeTerritory, XmlTrustServiceStatusList.NamespaceURI, true);
      this.StatusDeterminationApproach = value.childNodes[i].textContent!;

      // PolicyOrLegalNotice
      i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.PolicyOrLegalNotice, XmlTrustServiceStatusList.NamespaceURI, true);

      // HistoricalInformationPeriod
      i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.HistoricalInformationPeriod, XmlTrustServiceStatusList.NamespaceURI, true);
      this.HistoricalInformationPeriod = +value.childNodes[i].textContent!;

      // PointersToOtherTSL
      i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.PointersToOtherTSL, XmlTrustServiceStatusList.NamespaceURI, true);
      let pointers = value.childNodes[i].childNodes;
      for (let j = 0; j < pointers.length; j++) {
        // OtherTSLPointer
        let node = pointers[j];
        if (node.nodeType !== XmlNodeType.Element)
          continue;

        let pointer = new Pointer();
        pointer.LoadXml(node as Element);
        this.Pointers.push(pointer);
      }

    }
    else
      throw new Error("Wrong XML element");
  }
}

class Pointer extends XmlObject {

  public Location: string | null = null;
  public X509Certificates: string[] = [];
  public AdditionalInformation: AdditionalInformation | null = null;

  LoadXml(value: Element): void {
    if (value == null)
      throw new Error("Parameter 'value' is required");

    if ((value.localName === XmlTrustServiceStatusList.ElementNames.OtherTSLPointer) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
      // ServiceDigitalIdentities
      let i = this.NextElementPos(value.childNodes, 0, XmlTrustServiceStatusList.ElementNames.ServiceDigitalIdentities, XmlTrustServiceStatusList.NamespaceURI, true);
      let serviceDigitalIdentities = value.childNodes[i].childNodes;
      for (let j = 0; j < serviceDigitalIdentities.length; j++) {
        if (serviceDigitalIdentities[j].nodeType !== XmlNodeType.Element)
          continue;
        // X509Certificate
        let elsX509 = (serviceDigitalIdentities[j] as Element).getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.X509Certificate);
        for (let k = 0; k < elsX509.length; k++)
          this.X509Certificates.push(elsX509[k].textContent!);
      }

      // TSLLocation
      i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.TSLLocation, XmlTrustServiceStatusList.NamespaceURI, true);
      this.Location = value.childNodes[i].textContent;

      // AdditionalInformation
      i = this.NextElementPos(value.childNodes, ++i, XmlTrustServiceStatusList.ElementNames.AdditionalInformation, XmlTrustServiceStatusList.NamespaceURI, true);
      this.AdditionalInformation = new AdditionalInformation();
      this.AdditionalInformation.LoadXml(value.childNodes[i] as Element);
    }
    else
      throw new Error("Wrong XML element");
  }
}

class AdditionalInformation extends XmlObject {

  public TSLType: string | null = null;
  public SchemeTerritory: string | null = null;
  public SchemeOperatorName = new SchemeOperatorName();
  public SchemeTypeCommunityRules: string[] = [];
  public MimeType: string | null = null;

  LoadXml(value: Element): void {
    if (value == null)
      throw new Error("Parameter 'value' is required");

    if ((value.localName === XmlTrustServiceStatusList.ElementNames.AdditionalInformation) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
      // Search for OtherInformation
      let OtherInformationList = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.OtherInformation);
      for (let i = 0; i < OtherInformationList.length; i++) {
        // get first element
        let node = this.GetFirstElement(OtherInformationList[i].childNodes);
        if (XmlCore.isElement(node)) {
          switch (node.localName) {
            case XmlTrustServiceStatusList.ElementNames.SchemeTerritory:
              this.SchemeTerritory = node.textContent;
              break;
            case XmlTrustServiceStatusList.ElementNames.TSLType:
              this.TSLType = node.textContent;
              break;
            case XmlTrustServiceStatusList.ElementNames.SchemeOperatorName:
              this.SchemeOperatorName.LoadXml(node as Element);
              break;
            case XmlTrustServiceStatusList.ElementNames.SchemeTypeCommunityRules:
              let elements = (node as Element).getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.URI);
              for (let j = 0; j < elements.length; j++) {
                this.SchemeTypeCommunityRules.push(elements[j].textContent!);
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
  }

  protected GetFirstElement(nl: NodeList) {
    for (let i = 0; i < nl.length; i++) {
      let node = nl[i];
      if (node.nodeType !== XmlNodeType.Element)
        continue;
      return node;
    }
    return null;
  }

}

interface MultiLangItem<T> {
  item: T;
  lang: string;
}

class MultiLangType<T> extends XmlObject {

  protected m_elements: MultiLangItem<T>[] = [];

  GetItem(lang: string): T | null {
    for (let item of this.m_elements) {
      if (item.lang = lang)
        return item.item;
    }
    return null;
  }

  protected GetLang(el: Element): string | null {
    let lang = this.GetAttribute(el, "xml:lang");
    return lang || null;
  }

  public AddItem(el: T, lang: string): void {
    this.m_elements.push({ item: el, lang: lang });
  }


}

class SchemeOperatorName extends MultiLangType<string> {
  LoadXml(value: Element): void {
    if (value == null)
      throw new Error("Parameter 'value' is required");

    if ((value.localName === XmlTrustServiceStatusList.ElementNames.SchemeOperatorName) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
      // Search for OtherInformation
      let elements = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.Name);
      for (let i = 0; i < elements.length; i++) {
        let element = elements[i];
        let lang = this.GetLang(element);
        if (!lang)
          throw new Error("SchemeOperatorName:Name has no xml:lang attribute");
        this.AddItem(element.textContent!, lang);
      }
    }
    else
      throw new Error("Wrong XML element");
  }
}

class TrustServiceProvider extends XmlObject {
  public TSPName: TSPName | null = null;
  public TSPServices: TSPService[] = [];

  LoadXml(value: Element): void {
    if (value == null)
      throw new Error("Parameter 'value' is required");

    if ((value.localName === XmlTrustServiceStatusList.ElementNames.TrustServiceProvider) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
      let TSPNameNodes = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.TSPName);
      if (TSPNameNodes.length > 0) {
        this.TSPName = new TSPName();
        this.TSPName.LoadXml(TSPNameNodes[0] as Element);
      }

      let TSPServiceNodes = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.TSPService);
      for (let i = 0; i < TSPServiceNodes.length; i++) {
        let TSPServiceNode = TSPServiceNodes[i];
        let tSPService = new TSPService();
        tSPService.LoadXml(TSPServiceNode);
        this.TSPServices.push(tSPService);
      }
    }
    else
      throw new Error("Wrong XML element");
  }
}

class TSPService extends XmlObject {
  X509Certificates: string[] = [];
  ServiceTypeIdentifier: string | null = null;

  LoadXml(value: Element): void {
    if (value == null)
      throw new Error("Parameter 'value' is required");

    if ((value.localName === XmlTrustServiceStatusList.ElementNames.TSPService) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
      let ServiceTypeIdentifierNodes = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.ServiceTypeIdentifier);
      if (ServiceTypeIdentifierNodes.length > 0)
        this.ServiceTypeIdentifier = ServiceTypeIdentifierNodes[0].textContent;

      let DigitalIdNodes = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.DigitalId);
      for (let i = 0; i < DigitalIdNodes.length; i++) {
        let DigitalId = DigitalIdNodes[i] as Element;
        let X509CertificateNodes = DigitalId.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.X509Certificate);
        for (let j = 0; j < X509CertificateNodes.length; j++) {
          this.X509Certificates.push(X509CertificateNodes[j].textContent!);
        }
      }
    }
    else
      throw new Error("Wrong XML element");
  }
}

class TSPName extends MultiLangType<string> {
  LoadXml(value: Element): void {
    if (value == null)
      throw new Error("Parameter 'value' is required");

    if ((value.localName === XmlTrustServiceStatusList.ElementNames.TSPName) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
      // Search for OtherInformation
      let elements = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.Name);
      for (let i = 0; i < elements.length; i++) {
        let element = elements[i];
        let lang = this.GetLang(element);
        if (!lang)
          throw new Error("TSPName:Name has no xml:lang attribute");
        this.AddItem(element.textContent!, lang);
      }
    }
    else
      throw new Error("Wrong XML element");
  }
}
