/// <reference path="../typings/node/node.d.ts" />
/// <reference path="../typings/mocha/mocha.d.ts" />

var xadesjs = require("xadesjs");
global.xadesjs = xadesjs; 
var tl_create = require("../built/tl-create");
console.log("tl_createt", tl_create);
var assert = require("assert");

describe("TrustedList format", function () {

    it("Add certificate to trusted list", function () {
        var tl = new tl_create.TrustedList();

        assert.equal(tl.Certificates.length, 0, "Wrong Certificates length");

        tl.AddCertificate({ raw: new Uint8Array([1]) });
        tl.AddCertificate({ raw: new Uint8Array([2]) });
        tl.AddCertificate({ raw: new Uint8Array([3]) });

        assert.equal(tl.Certificates.length, 3, "Wrong Certificates length");
    })
    
    it("Convert trusted list to JSON", function(){
        var tl = new tl_create.TrustedList();

        assert.equal(tl.Certificates.length, 0, "Wrong Certificates length");

        tl.AddCertificate({ raw: new Uint8Array([1]) });
        
        var json = JSON.stringify(tl);
        
        assert.equal(json, "[\"AQ==\"]");
    })
    
    it("Convert trusted list to String", function(){
        var tl = new tl_create.TrustedList();

        assert.equal(tl.Certificates.length, 0, "Wrong Certificates length");

        tl.AddCertificate({ raw: new Uint8Array([1]) });
        tl.AddCertificate({ raw: new Uint8Array([2]) });
        
        var text = tl.toString();
        
        assert.equal(text, "AQ==\nAg==");
    })

})