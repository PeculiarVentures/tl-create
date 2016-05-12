/// <reference path="../typings/node/node.d.ts" />
/// <reference path="../typings/mocha/mocha.d.ts" />

global.DOMParser = require("xmldom").DOMParser;
var xadesjs = require("xadesjs");
global.xadesjs = xadesjs;
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
        assert.equal(eutl.SchemaInformation.Pointers.length, 48);
        assert.equal(eutl.SchemaInformation.Pointers[0].X509Certificates.length, 2);
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

    it("EUTL parse", function () {
        // get static file
        var eutlText = fs.readFileSync("./test/static/eutl.xml", "utf8");

        var eutl = new tl_create.EUTL();
        var tl = eutl.parse(eutlText);
        assert.equal(tl.Certificates.length, 101);
    });

})