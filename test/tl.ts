import * as assert from "assert";
import * as fs from "fs";
import * as tl_create from "../src";

describe("TrustedList format", function () {

    it("Add certificate to trusted list", function () {
        let tl = new tl_create.TrustedList();

        assert.strictEqual(tl.Certificates.length, 0, "Wrong Certificates length");

        tl.AddCertificate({ raw: "A1==" });
        tl.AddCertificate({ raw: "A2==" });
        tl.AddCertificate({ raw: "A3==" });

        assert.strictEqual(tl.Certificates.length, 3, "Wrong Certificates length");
    });

    it("Convert trusted list to JSON", function () {
        let tl = new tl_create.TrustedList();

        assert.strictEqual(tl.Certificates.length, 0, "Wrong Certificates length");

        tl.AddCertificate({ raw: "AQ==" });

        let json = JSON.stringify(tl);

        assert.strictEqual(json, "[{\"raw\":\"AQ==\"}]");
    });

    it("Convert trusted list to String", function () {
        let tl = new tl_create.TrustedList();

        assert.strictEqual(tl.Certificates.length, 0, "Wrong Certificates length");

        tl.AddCertificate({ raw: "A1==", operator: "Operator 1", trust: ["FILTER1"], source: "Source1", evpolicy: ["0.1.2"] });

        let text = tl.toString();

        assert.strictEqual(text, "Operator: Operator 1\nSource: Source1\nEV OIDs: 0.1.2\n-----BEGIN CERTIFICATE-----\nA1==\n-----END CERTIFICATE-----");
    });

    it("Filter", function () {
        let tl = new tl_create.TrustedList();

        assert.strictEqual(tl.Certificates.length, 0, "Wrong Certificates length");

        tl.AddCertificate({ raw: "A1==", operator: "Operator 1", trust: ["FILTER1"], source: "Source1", });
        tl.AddCertificate({ raw: "A2==", operator: "Operator 2", trust: ["FILTER2"], source: "Source2", });

        let filtered_tl = tl.filter(function(item, index) {
            return item.source === "Source1";
        });

        assert.strictEqual(filtered_tl.Certificates.length, 1);
        assert.strictEqual(tl.Certificates.length, 1);
    });

    it("Concatenate trusted lists", function () {
        let tl1 = new tl_create.TrustedList();

        assert.strictEqual(tl1.Certificates.length, 0, "Wrong Certificates length");

        tl1.AddCertificate({ raw: "A" });
        tl1.AddCertificate({ raw: "B" });

        let tl2 = new tl_create.TrustedList();

        assert.strictEqual(tl2.Certificates.length, 0, "Wrong Certificates length");

        tl2.AddCertificate({ raw: "C" });
        tl2.AddCertificate({ raw: "D" });

        let tl = tl1.concat(tl2);
        assert.strictEqual(tl.Certificates.length, 4, "Wrong Certificates length, should be 4");
        assert.strictEqual(tl1.Certificates.length, 4, "Wrong Certificates length, should be 4");
    });

});
