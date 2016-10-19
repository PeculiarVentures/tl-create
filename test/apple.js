/// <reference path="../typings/node/node.d.ts" />
/// <reference path="../typings/mocha/mocha.d.ts" />

var xadesjs = require("xadesjs");
global.xadesjs = xadesjs;
var asn1js = require("asn1js");
global.asn1js = asn1js;
var request = require("sync-request");
global.request = request;
var cheerio = require("cheerio");
global.cheerio = cheerio;
var tl_create = require("../built/tl-create");
var assert = require("assert");

var fs = require("fs");

describe("Apple format", function () {

    it("Parse incoming text for trusted roots", function () {
        // get static file
        var appleTLListText = fs.readFileSync("./test/static/apple_tl_list.html", "utf8");
        var appleCertListText = fs.readFileSync("./test/static/apple_cert_list.html", "utf8");
        var appleEVRootText = fs.readFileSync("./test/static/apple_evroot.config", "utf8");

        var ms = new tl_create.Apple();
        var tl = ms.getTrusted(appleTLListText, appleCertListText, appleEVRootText, true);
        
        assert.equal(tl.Certificates.length, 188);
    });

    it("Parse incoming text for disallowed roots", function () {
        // get static file
        var appleTLListText = fs.readFileSync("./test/static/apple_tl_list.html", "utf8");
        var appleCertListText = fs.readFileSync("./test/static/apple_dis_cert_list.html", "utf8");

        var ms = new tl_create.Apple();
        var tl = ms.getDisallowed(appleTLListText, appleCertListText, true);
        
        assert.equal(tl.Certificates.length, 12);
    });

})
