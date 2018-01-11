/// <reference path="../typings/node/node.d.ts" />
/// <reference path="../typings/mocha/mocha.d.ts" />

var xadesjs = require("xadesjs");
global.xadesjs = xadesjs;
var asn1js = require("asn1js");
global.asn1js = asn1js;
var request = require("sync-request");
global.request = request;
var Pkijs = require("pkijs");
global.Pkijs = Pkijs;
var WebCrypto = require("node-webcrypto-ossl");
webcrypto = new WebCrypto();
Pkijs.setEngine('OpenSSL', webcrypto, new Pkijs.CryptoEngine({
    name: 'OpenSSL',
    crypto: webcrypto,
    subtle: webcrypto.subtle
}));
var tl_create = require("../built/tl-create");
var assert = require("assert");

var fs = require("fs");

describe("Cisco format", function () {

    it("Parse incoming text for external root bundle", function () {
        this.timeout(15000);

        // get static file
        var ciscoText = fs.readFileSync("./test/static/ios.p7b", "binary");

        var cisco = new tl_create.Cisco("external");
        var tl = cisco.getTrusted(ciscoText);

        assert.equal(tl.Certificates.length, 132);
    });

    it("Parse incoming text for union root bundle", function () {
        this.timeout(15000);

        // get static file
        var ciscoText = fs.readFileSync("./test/static/ios_union.p7b", "binary");

        var cisco = new tl_create.Cisco("union");
        var tl = cisco.getTrusted(ciscoText);

        assert.equal(tl.Certificates.length, 367);
    });

    it("Parse incoming text for core root bundle", function () {
        this.timeout(15000);

        // get static file
        var ciscoText = fs.readFileSync("./test/static/ios_core.p7b", "binary");

        var cisco = new tl_create.Cisco("core");
        var tl = cisco.getTrusted(ciscoText);

        assert.equal(tl.Certificates.length, 17);
    });

    it("Check PKCS#7 signature", function (done) {
        this.timeout(15000);

        // get static file
        var ciscoText = fs.readFileSync("./test/static/ios_core.p7b", "binary");

        var cisco = new tl_create.Cisco("core");
        var tl = cisco.getTrusted(ciscoText);
        cisco.verifyP7().then(function (v) {
            assert.equal(v, true, "Wrong signature");
            done();
        }).catch(done);
    });

})
