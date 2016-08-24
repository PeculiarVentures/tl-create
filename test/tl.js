var xadesjs = require("xadesjs");
global.xadesjs = xadesjs;
var tl_create = require("../built/tl-create");
var assert = require("assert");

describe("TrustedList format", function () {

    it("Add certificate to trusted list", function () {
        var tl = new tl_create.TrustedList();

        assert.equal(tl.Certificates.length, 0, "Wrong Certificates length");

        tl.AddCertificate({ raw: "A1==" });
        tl.AddCertificate({ raw: "A2==" });
        tl.AddCertificate({ raw: "A3==" });

        assert.equal(tl.Certificates.length, 3, "Wrong Certificates length");
    })

    it("Convert trusted list to JSON", function () {
        var tl = new tl_create.TrustedList();

        assert.equal(tl.Certificates.length, 0, "Wrong Certificates length");

        tl.AddCertificate({ raw: "AQ==" });

        var json = JSON.stringify(tl);

        assert.equal(json, "[{\"raw\":\"AQ==\"}]");
    })

    it("Convert trusted list to String", function () {
        var tl = new tl_create.TrustedList();

        assert.equal(tl.Certificates.length, 0, "Wrong Certificates length");

        tl.AddCertificate({ raw: "A1==", operator: "Operator 1", trust: ["FILTER1"], source: "Source1", });

        var text = tl.toString();

        assert.equal(text, "Operator: Operator 1\nSource: Source1\n-----BEGIN CERTIFICATE-----\nA1==\n-----END CERTIFICATE-----");
    })

    it("Filter", function () {
        var tl = new tl_create.TrustedList();

        assert.equal(tl.Certificates.length, 0, "Wrong Certificates length");

        tl.AddCertificate({ raw: "A1==", operator: "Operator 1", trust: ["FILTER1"], source: "Source1", });
        tl.AddCertificate({ raw: "A2==", operator: "Operator 2", trust: ["FILTER2"], source: "Source2", });

        var filtered_tl = tl.filter(function(item, index) {
            return item.source === "Source1";
        })

        assert.equal(filtered_tl.Certificates.length, 1);
        assert.equal(tl.Certificates.length, 1);
    })

    it("Concatinate trusted lists", function () {
        var tl1 = new tl_create.TrustedList();

        assert.equal(tl1.Certificates.length, 0, "Wrong Certificates length");

        tl1.AddCertificate({ raw: new Uint8Array([1]) });
        tl1.AddCertificate({ raw: new Uint8Array([2]) });

        var tl2 = new tl_create.TrustedList();

        assert.equal(tl2.Certificates.length, 0, "Wrong Certificates length");

        tl2.AddCertificate({ raw: new Uint8Array([1]) });
        tl2.AddCertificate({ raw: new Uint8Array([2]) });

        var tl = tl1.concat(tl2);
        assert.equal(tl.Certificates.length, 4, "Wrong Certificates length, should be 4");
        assert.equal(tl1.Certificates.length, 4, "Wrong Certificates length, should be 4");
    })

})