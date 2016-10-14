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

describe("Mozilla format", function () {

    it("Parse incoming text", function () {
        // get static file
        var mozText = fs.readFileSync("./test/static/mozilla.txt", "utf8");

        var moz = new tl_create.Mozilla();
        var tl = moz.parse(mozText);
        
        assert.equal(tl.Certificates.length, 177);
    });

})
