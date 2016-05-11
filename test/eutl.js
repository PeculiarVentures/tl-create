/// <reference path="../typings/node/node.d.ts" />
/// <reference path="../typings/mocha/mocha.d.ts" />

var DOMParser = require("xmldom").DOMParser;
var xadesjs = require("xadesjs");
global.xadesjs = xadesjs;
var tl_create = require("../built/tl-create");
console.log("tl_createt", tl_create);
var assert = require("assert");

var fs = require("fs");

describe("EUTL format", function () {

    it("Test 1", function () {
        // get static file
        var eutlText = fs.readFileSync("./test/static/eitl.xml", "utf8");

        var eutl = new tl_create.TrustServiceStatusList();
        var xml = new DOMParser().parseFromString(eutlText, "application/xml");
        eutl.LoadXml(xml);
        
    })

})