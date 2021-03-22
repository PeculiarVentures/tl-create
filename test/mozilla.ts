import * as assert from "assert";
import * as fs from "fs";
import * as tl_create from "../src";

describe("Mozilla format", () => {

  it("Parse incoming text for trusted roots", () => {
    // get static file
    let mozText = fs.readFileSync("./test/static/mozilla.txt", "utf8");

    let moz = new tl_create.Mozilla();
    let tl = moz.getTrusted(mozText);

    assert.strictEqual(tl.Certificates.length, 157);
  });

  it("Parse incoming text for disallowed roots", () => {
    // get static file
    let mozText = fs.readFileSync("./test/static/mozilla.txt", "utf8");

    let moz = new tl_create.Mozilla();
    let tl = moz.getDisallowed(mozText);

    assert.strictEqual(tl.Certificates.length, 19);
  });

});
