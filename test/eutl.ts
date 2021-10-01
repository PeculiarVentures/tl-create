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

  it("EU EUTL parse", async () => {
    // get static file
    let eutlText = fs.readFileSync("./test/static/eutl.xml", "utf8");

    let eutl = new tl_create.EUTL();
    let tl = await eutl.getTrusted(eutlText);
    assert.strictEqual(tl.Certificates.length, 0);
  });

  it("Member-state EUTL parse", async() => {
    // get static file
    let eutlText = fs.readFileSync("./test/static/EL-TSL.xml", "utf8");

    let eutl = new tl_create.EUTL();
    let tl = await eutl.getTrusted(eutlText);
    assert.strictEqual(tl.Certificates.length, 23);
  });

});
