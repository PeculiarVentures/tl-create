import * as assert from "assert";
import * as fs from "fs";
import * as tl_create from "../src";

describe("EUTL format", function() {

  it("TrustServiceStatusList LoadXML", function() {
    // get static file
    let eutlText = fs.readFileSync("./test/static/eutl.xml", "utf8");

    let eutl = new tl_create.TrustServiceStatusList();
    let xml = new DOMParser().parseFromString(eutlText, "application/xml");
    eutl.LoadXml(xml);
    assert.equal(eutl.SchemaInformation.Pointers.length, 46);
    assert.equal(eutl.SchemaInformation.Pointers[0].X509Certificates.length, 5);
  });

  it("TrustServiceStatusList check signature", async () => {
    // get static file
    let eutlText = fs.readFileSync("./test/static/eutl.xml", "utf8");

    let eutl = new tl_create.TrustServiceStatusList();
    let xml = new DOMParser().parseFromString(eutlText, "application/xml");
    eutl.LoadXml(xml);

    const v = await eutl.CheckSignature();
    assert.equal(v, true, "Wrong signature");
  });

  it("EU EUTL parse", function() {
    // get static file
    let eutlText = fs.readFileSync("./test/static/eutl.xml", "utf8");

    let eutl = new tl_create.EUTL();
    let tl = eutl.getTrusted(eutlText);
    assert.equal(tl.Certificates.length, 0);
  });

  it("Member-state EUTL parse", function() {
    // get static file
    let eutlText = fs.readFileSync("./test/static/EL-TSL.xml", "utf8");

    let eutl = new tl_create.EUTL();
    let tl = eutl.getTrusted(eutlText);
    assert.equal(tl.Certificates.length, 23);
  });

});
