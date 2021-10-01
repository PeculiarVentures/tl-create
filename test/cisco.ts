import * as assert from "assert";
import * as fs from "fs";
import * as tl_create from "../src";

describe("Cisco format", () => {

  it("Parse incoming text for external root bundle", async () => {
    // get static file
    let ciscoText = fs.readFileSync("./test/static/ios.p7b", "binary");

    let cisco = new tl_create.Cisco("external");
    let tl = await cisco.getTrusted(ciscoText);

    assert.strictEqual(tl.Certificates.length, 132);
  });

  it("Parse incoming text for union root bundle", async () => {
    // get static file
    let ciscoText = fs.readFileSync("./test/static/ios_union.p7b", "binary");

    let cisco = new tl_create.Cisco("union");
    let tl = await cisco.getTrusted(ciscoText);

    assert.strictEqual(tl.Certificates.length, 367);
  });

  it("Parse incoming text for core root bundle", async () => {
    // get static file
    let ciscoText = fs.readFileSync("./test/static/ios_core.p7b", "binary");

    let cisco = new tl_create.Cisco("core");
    let tl = await cisco.getTrusted(ciscoText);

    assert.strictEqual(tl.Certificates.length, 17);
  });

  it("Check PKCS#7 signature", async () => {
    // get static file
    let ciscoText = fs.readFileSync("./test/static/ios_core.p7b", "binary");

    let cisco = new tl_create.Cisco("core");
    await cisco.getTrusted(ciscoText);
    const v = await cisco.verifyP7();
    assert.strictEqual(v, true, "Wrong signature");
  });

});
