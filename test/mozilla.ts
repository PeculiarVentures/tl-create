import * as assert from "assert";
import * as fs from "fs";
import * as tl_create from "../src";

describe("Mozilla format", function() {

  it("Parse incoming text for trusted roots", function() {
    // get static file
    let mozText = fs.readFileSync("./test/static/mozilla.txt", "utf8");

    let moz = new tl_create.Mozilla();
    let tl = moz.getTrusted(mozText);

    assert.equal(tl.Certificates.length, 157);
  });

  it("Parse incoming text for disallowed roots", function() {
    // get static file
    let mozText = fs.readFileSync("./test/static/mozilla.txt", "utf8");

    let moz = new tl_create.Mozilla();
    let tl = moz.getDisallowed(mozText);

    assert.equal(tl.Certificates.length, 19);
  });

});
