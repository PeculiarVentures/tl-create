import * as assert from "assert";
import * as fs from "fs";
// TODO: fix ignore below
// @ts-ignore - no "build" dir @types for this package, but src contains disallowed import
import Certificate from "pkijs/build/Certificate";
import * as pvutils from "pvutils";
import * as asn1js from "asn1js";
import * as tl_create from "../src";

describe("AATL format", () => {

  it("AATL parse", async () => {
    // get static file
    let aatlSettingsText = fs.readFileSync("./test/static/AdobeSecuritySettings.xml", "utf8");

    let aatl = new tl_create.AATL();

    let tl = await aatl.getTrusted(aatlSettingsText);

    assert.strictEqual(tl.Certificates.length, 263);
  });

  it("AATL parse from static file PDF", async () => {
    let aatl = new tl_create.AATL({ url: "./test/static/tl12.acrobatsecuritysettings" });

    let tl = await aatl.getTrusted();

    assert.strictEqual(tl.Certificates.length, 263);
  });

  it("AATL contains Adobe Root with valid info", async () => {
    // use static test file
    let aatlSettingsText = fs.readFileSync("./test/static/AdobeSecuritySettings.xml", "utf8");

    let aatl = new tl_create.AATL();

    let tl = await aatl.getTrusted(aatlSettingsText);

    const cert = tl.Certificates.find(cert => {
      let PKICertificate = Certificate;

      let fileRaw = pvutils.stringToArrayBuffer(pvutils.fromBase64(cert.raw));

      let asn1 = asn1js.fromBER(fileRaw);

      const certificate = new PKICertificate({ schema: asn1.result });
      const cn = certificate.subject.typesAndValues.find((el: any) => el.type === "2.5.4.3");

      if (cn?.value?.valueBlock?.value === "Adobe Root CA G2") {
        return true;
      }

      return false;
    });

    assert.strictEqual(!!cert, true);
    assert.notStrictEqual(cert?.trust, ["ROOT", "CERTIFIED_DOCUMENTS"]);
    assert.notStrictEqual(cert?.evpolicy, []);
    assert.strictEqual(cert?.source, "AATL");
  });

  it("AATL getDisallowed", async () => {
    // get static file
    let aatlSettingsText = fs.readFileSync("./test/static/AdobeSecuritySettings.xml", "utf8");

    let aatl = new tl_create.AATL();

    let tl = await aatl.getDisallowed(aatlSettingsText);

    assert.strictEqual(tl.Certificates.length, 67);

    // ensure item has no trust flags
    assert.notStrictEqual(tl.Certificates[0].trust, []);
  });
});
