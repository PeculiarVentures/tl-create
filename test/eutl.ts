import * as assert from "assert";
import * as fs from "fs";
import * as tl_create from "../src";

describe("EUTL format", () => {

  it("TrustServiceStatusList LoadXML", () => {
    // get static file
    let eutlText = fs.readFileSync("./test/static/eutl.xml", "utf8");

    let eutl = new tl_create.TrustServiceStatusList();
    let xml = new DOMParser().parseFromString(eutlText, "application/xml");
    eutl.LoadXml(xml);
    assert.strictEqual(eutl.SchemaInformation.Pointers.length, 46);
    assert.strictEqual(eutl.SchemaInformation.Pointers[0].X509Certificates.length, 5);
  });

  it("TrustServiceStatusList check signature", async () => {
    // get static file
    let eutlText = fs.readFileSync("./test/static/eutl.xml", "utf8");

    let eutl = new tl_create.TrustServiceStatusList();
    let xml = new DOMParser().parseFromString(eutlText, "application/xml");
    eutl.LoadXml(xml);

    const v = await eutl.CheckSignature();
    assert.strictEqual(v, true, "Wrong signature");
  });

  it("TrustServiceStatusList verifies RSA-PSS signatures from the German TSL fixture", async () => {
    let eutlText = fs.readFileSync("./test/static/TL-DE-2026-02-rsa-pss.xml", "utf8");

    let eutl = new tl_create.TrustServiceStatusList();
    let xml = new DOMParser().parseFromString(eutlText, "application/xml");
    eutl.LoadXml(xml);

    const v = await eutl.CheckSignature();
    assert.strictEqual(v, true, "Wrong RSA-PSS fixture signature");
  });

  it("EU EUTL parse", () => {
    // get static file
    let eutlText = fs.readFileSync("./test/static/eutl.xml", "utf8");

    let eutl = new tl_create.EUTL();
    let tl = eutl.getTrusted(eutlText);
    assert.strictEqual(tl.Certificates.length, 0);
  });

  it("Member-state EUTL parse", () => {
    // get static file
    let eutlText = fs.readFileSync("./test/static/EL-TSL.xml", "utf8");

    let eutl = new tl_create.EUTL();
    let tl = eutl.getTrusted(eutlText);
    assert.strictEqual(tl.Certificates.length, 23);
  });

  it("EUTL parse excludes historical service certificates", () => {
    const eutlXml = `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="TEST-TL" TSLTag="http://uri.etsi.org/19612/TSLTag">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType>
    <SchemeOperatorName><Name xml:lang="en">Test Operator</Name></SchemeOperatorName>
    <SchemeOperatorAddress><PostalAddresses><PostalAddress xml:lang="en"><StreetAddress>1 Street</StreetAddress><Locality>City</Locality><PostalCode>1234</PostalCode><CountryName>XX</CountryName></PostalAddress></PostalAddresses><ElectronicAddress><URI>mailto:info@test.com</URI></ElectronicAddress></SchemeOperatorAddress>
    <SchemeName><Name xml:lang="en">Test List</Name></SchemeName>
    <SchemeInformationURI><URI>http://test.com</URI></SchemeInformationURI>
    <StatusDeterminationApproach>http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate</StatusDeterminationApproach>
    <SchemeTypeCommunityRules><URI>http://rules</URI></SchemeTypeCommunityRules>
    <SchemeTerritory>XX</SchemeTerritory>
    <PolicyOrLegalNotice><TSLLegalNotice xml:lang="en">Notice</TSLLegalNotice></PolicyOrLegalNotice>
    <HistoricalInformationPeriod>65535</HistoricalInformationPeriod>
    <PointersToOtherTSL></PointersToOtherTSL>
    <ListIssueDateTime>2026-06-09T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2026-12-09T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="en">Test TSP</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Active Service</Name></ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId>
                <X509Certificate>ACTIVE_CERT_BYTES</X509Certificate>
              </DigitalId>
            </ServiceDigitalIdentity>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <StatusStartingTime>2026-06-09T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
          <ServiceHistory>
            <ServiceHistoryInstance>
              <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
              <ServiceName><Name xml:lang="en">Historical Service</Name></ServiceName>
              <ServiceDigitalIdentity>
                <DigitalId>
                  <X509Certificate>HISTORICAL_CERT_BYTES</X509Certificate>
                </DigitalId>
              </ServiceDigitalIdentity>
              <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn</ServiceStatus>
              <StatusStartingTime>2020-06-09T00:00:00Z</StatusStartingTime>
            </ServiceHistoryInstance>
          </ServiceHistory>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`;

    const eutl = new tl_create.EUTL();
    const tl = eutl.getTrusted(eutlXml);
    assert.strictEqual(tl.Certificates.length, 1);
    assert.strictEqual(tl.Certificates[0].raw, "ACTIVE_CERT_BYTES");
  });

});
