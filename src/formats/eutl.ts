namespace tl_create {

    export class EUTL {

        TrustServiceStatusList: TrustServiceStatusList = null;

        parse(data: string): TrustedList {
            let eutl = new tl_create.TrustServiceStatusList();
            let xml = new DOMParser().parseFromString(data, "application/xml");
            eutl.LoadXml(xml);
            this.TrustServiceStatusList = eutl;
            let tl = new TrustedList();
            for (let pointer of eutl.SchemaInformation.Pointers)
                for (let cert of pointer.X509Certificates)
                    tl.AddCertificate({
                        raw: cert,
                        trust: pointer.AdditionalInformation.SchemeTypeCommunityRules,
                        operator: pointer.AdditionalInformation.SchemeOperatorName.GetItem("en"),
                        source: "EUTL"
                    });
            return tl;
        }
    }

    export let XmlNodeType = xadesjs.XmlNodeType;

    abstract class XmlObject extends xadesjs.XmlObject {

        protected GetAttribute(node: Element, name: string, defaultValue: string = null): string {
            return node.hasAttribute(name) ? node.getAttribute(name) : defaultValue;
        }

        protected NextElementPos(nl: NodeList, pos: number, name: string, ns: string, required: boolean): number {
            while (pos < nl.length) {
                if (nl[pos].nodeType === XmlNodeType.Element) {
                    if (nl[pos].localName !== name || nl[pos].namespaceURI !== ns) {
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
        },

        AttributeNames: {
            Id: "Id",
            TSLTag: "TSLTag"
        },

        NamespaceURI: "http://uri.etsi.org/02231/v2#"
    };

    export class TrustServiceStatusList extends XmlObject {

        Id: string = null;
        TSLTag: string = null;
        SchemaInformation: SchemeInformation = null;

        LoadXml(value: Node): void {
            if (value == null)
                throw new Error("Parameter 'value' is required");

            if ((value as any).constructor.name === "Document" || value instanceof Document)
                value = (value as any).documentElement;


            if ((value.localName === XmlTrustServiceStatusList.ElementNames.TrustServiceStatusList) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
                // Id
                this.Id = this.GetAttribute(value as Element, XmlTrustServiceStatusList.AttributeNames.Id);
                // TSLTag
                this.TSLTag = this.GetAttribute(value as Element, XmlTrustServiceStatusList.AttributeNames.TSLTag);

                this.SchemaInformation = new SchemeInformation();

                let i = this.NextElementPos(value.childNodes, 0, XmlTrustServiceStatusList.ElementNames.SchemeInformation, XmlTrustServiceStatusList.NamespaceURI, true);
                this.SchemaInformation.LoadXml(value.childNodes[i] as Element);
            }
            else
                throw new Error("Wrong XML element");
        }
    }

    class SchemeInformation extends XmlObject {

        Version: number;
        SequenceNumber: number;
        Type: string;
        StatusDeterminationApproach: string;
        SchemeTerritory: string;
        HistoricalInformationPeriod: number;
        Pointers: Pointer[] = [];

        LoadXml(value: Element): void {
            if (value == null)
                throw new Error("Parameter 'value' is required");

            if ((value.localName === XmlTrustServiceStatusList.ElementNames.SchemeInformation) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {

                // TSLVersionIdentifier
                let i = this.NextElementPos(value.childNodes, 0, XmlTrustServiceStatusList.ElementNames.TSLVersionIdentifier, XmlTrustServiceStatusList.NamespaceURI, true);
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

        Location: string = null;
        X509Certificates: string[] = [];
        AdditionalInformation: AdditionalInformation = null;

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
                        this.X509Certificates.push(elsX509[k].textContent);
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

        TSLType: string = null;
        SchemeTerritory: string = null;
        SchemeOperatorName = new SchemeOperatorName();
        SchemeTypeCommunityRules: string[] = [];

        LoadXml(value: Element): void {
            if (value == null)
                throw new Error("Parameter 'value' is required");

            if ((value.localName === XmlTrustServiceStatusList.ElementNames.AdditionalInformation) && (value.namespaceURI === XmlTrustServiceStatusList.NamespaceURI)) {
                // Search for OtherInformation
                let OtherInformationList = value.getElementsByTagNameNS(XmlTrustServiceStatusList.NamespaceURI, XmlTrustServiceStatusList.ElementNames.OtherInformation);
                for (let i = 0; i < OtherInformationList.length; i++) {
                    // get first element
                    let node = this.GetFirstElement(OtherInformationList[i].childNodes);
                    if (node) {
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
                                    this.SchemeTypeCommunityRules.push(elements[j].textContent);
                                }
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

        GetItem(lang: string): T {
            for (let item of this.m_elements) {
                if (item.lang = lang)
                    return item.item;
            }
            return null;
        }

        protected GetLang(el: Element): string {
            let lang = this.GetAttribute(el, "xml:lang");
            return lang || null;
        }

        AddItem(el: T, lang: string): void {
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
                    this.AddItem(element.textContent, lang);
                }
            }
            else
                throw new Error("Wrong XML element");
        }
    }

}