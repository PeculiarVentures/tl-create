/// <reference path="../typings/node/node.d.ts" />
/// <reference path="../typings/mocha/mocha.d.ts" />

var xadesjs = require("xadesjs");
global.xadesjs = xadesjs;
var asn1js = require("asn1js");
global.asn1js = asn1js;
var request = require("sync-request");
global.request = request;
var tl_create = require("../built/tl-create");
var assert = require("assert");

var fs = require("fs");

describe("Microsoft format", function () {

    it("Parse incoming text", function () {
        this.timeout(15000);

        // get static file
        var msText = fs.readFileSync("./test/static/authroot.stl", "base64");

        var ms = new tl_create.Microsoft();
        var tl = ms.parse(msText, true);
        
        assert.equal(tl.Certificates.length, 356);
    });

})
