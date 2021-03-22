import * as assert from "assert";
import * as fs from "fs";
import * as tl_create from "../src";

describe("Apple format", () => {

  it("Parse incoming text for trusted roots", () => {
    // get static file
    const appleTLListText = fs.readFileSync("./test/static/apple_tl_list.html", "utf8");
    const appleCertListText = fs.readFileSync("./test/static/apple_cert_list.html", "utf8");
    const appleEVRootText = fs.readFileSync("./test/static/apple_evroot.config", "utf8");

    const apple = new tl_create.Apple();
    const tl = apple.getTrusted(appleTLListText, appleCertListText, appleEVRootText, true);

    assert.strictEqual(tl.Certificates.length, 188);
  });

  it("Parse incoming text for disallowed roots", () => {
    // get static file
    let appleTLListText = fs.readFileSync("./test/static/apple_tl_list.html", "utf8");
    let appleCertListText = fs.readFileSync("./test/static/apple_dis_cert_list.html", "utf8");

    let apple = new tl_create.Apple();
    let tl = apple.getDisallowed(appleTLListText, appleCertListText, true);

    assert.strictEqual(tl.Certificates.length, 12);
  });

});
