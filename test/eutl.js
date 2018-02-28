/// <reference path="../typings/node/node.d.ts" />
/// <reference path="../typings/mocha/mocha.d.ts" />

global.DOMParser = require("xmldom-alpha").DOMParser;
var xadesjs = require("xadesjs");
global.xadesjs = xadesjs;
var asn1js = require("asn1js");
global.asn1js = asn1js;
var request = require("sync-request");
global.request = request;
var WebCrypto = require("node-webcrypto-ossl");
xadesjs.Application.setEngine("OpenSSL", new WebCrypto());
var tl_create = require("../built/tl-create");
var assert = require("assert");

var fs = require("fs");

describe("EUTL format", function () {

    it("TrustServiceStatusList LoadXML", function () {
        // get static file
        var eutlText = fs.readFileSync("./test/static/eutl.xml", "utf8");

        var eutl = new tl_create.TrustServiceStatusList();
        var xml = new DOMParser().parseFromString(eutlText, "application/xml");
        eutl.LoadXml(xml);
        assert.equal(eutl.SchemaInformation.Pointers.length, 46);
        assert.equal(eutl.SchemaInformation.Pointers[0].X509Certificates.length, 5);
    })

    it("TrustServiceStatusList check signature", function (done) {
        // get static file
        var eutlText = fs.readFileSync("./test/static/eutl.xml", "utf8");

        var eutl = new tl_create.TrustServiceStatusList();
        var xml = new DOMParser().parseFromString(eutlText, "application/xml");
        eutl.LoadXml(xml);

        eutl.CheckSignature()
            .then(function (v) {
                assert.equal(v, true, "Wrong signature");
                done();
            })
            .catch(done);
    });

    it("EU EUTL parse", function () {
        // get static file
        var eutlText = fs.readFileSync("./test/static/eutl.xml", "utf8");

        var eutl = new tl_create.EUTL();
        var tl = eutl.getTrusted(eutlText);
        assert.equal(tl.Certificates.length, 0);
    });

    it("Member-state EUTL parse", function () {
        // get static file
        var eutlText = fs.readFileSync("./test/static/EL-TSL.xml", "utf8");

        var eutl = new tl_create.EUTL();
        var tl = eutl.getTrusted(eutlText);
        assert.equal(tl.Certificates.length, 23);
    });

})
