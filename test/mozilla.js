/// <reference path="../typings/node/node.d.ts" />
/// <reference path="../typings/mocha/mocha.d.ts" />

var xadesjs = require("xadesjs");
global.xadesjs = xadesjs;
var tl_create = require("../built/tl-create");
console.log("tl_createt", tl_create);
var assert = require("assert");

var fs = require("fs");

describe("Mozilla format", function () {

    it("Test 1", function () {
        // get static file
        var mozText = fs.readFileSync("./test/static/mozilla.txt", "utf8");

        var moz = new tl_create.Mozilla();
        var tl = moz.parse(mozText);
        
        assert.equal(tl.Certificates.length, 177);
    })

})