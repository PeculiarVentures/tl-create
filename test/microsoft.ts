import * as assert from "assert";
import * as fs from "fs";
import * as tl_create from "../src";

describe("Microsoft format", () => {

  it("Parse incoming text for trusted roots", async () => {
    // get static file
    let msText = fs.readFileSync("./test/static/authroot.stl", "binary");

    let ms = new tl_create.Microsoft();
    let tl = await ms.getTrusted(msText, true);

    assert.strictEqual(tl.Certificates.length, 356);
  });

  it("Parse incoming text for disallowed roots", async () => {
    // get static file
    let msText = fs.readFileSync("./test/static/disallowedcert.stl", "binary");

    let ms = new tl_create.Microsoft();
    let tl =await  ms.getDisallowed(msText, true);

    assert.strictEqual(tl.Certificates.length, 64);
  });

});
