#!/usr/bin/env node

var program = require('commander');
var util = require('util');
//var request = require('sync-request');
global.request = require('sync-request');
global.xadesjs = require('xadesjs');
var merge = require("node.extend");
var common = require("asn1js/org/pkijs/common");
var _asn1js = require("asn1js");
global.asn1js = merge(true, _asn1js, common);
global.DOMParser = require('xmldom-alpha').DOMParser;
global.XMLSerializer = require('xmldom-alpha').XMLSerializer;
var WebCrypto = require("node-webcrypto-ossl");
xadesjs.Application.setEngine("OpenSSL", new WebCrypto());
var tl_create = require('../../built/tl-create.js');
var fs = require('fs');
var temp = require('temp').track();
var path = require('path');
var child_process = require('child_process');
var prefix = "tsl:";//used by eutl 
var euUrl = "http://ec.europa.eu/information_society/newsroom/cf/dae/document.cfm?doc_id=1789";
var mozillaUrl = "http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1";
var microsoftUrl = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab";
var isFirstOutput = true;
var totalRootCount = 0;
var parsedRootCount = 0;
var errorParsedRootCount = 0;
var totalRootsSkip = 0;

/*
 * Utility functions 
 * 
 */
function getDateTime() {

    var date = new Date();

    var hour = date.getHours();
    hour = (hour < 10 ? "0" : "") + hour;

    var min = date.getMinutes();
    min = (min < 10 ? "0" : "") + min;

    var sec = date.getSeconds();
    sec = (sec < 10 ? "0" : "") + sec;

    var year = date.getFullYear();

    var month = date.getMonth() + 1;
    month = (month < 10 ? "0" : "") + month;

    var day = date.getDate();
    day = (day < 10 ? "0" : "") + day;

    return year + ":" + month + ":" + day + ":" + hour + ":" + min + ":" + sec;

}

program
    .version('1.1.0')
    .option('-e, --eutl', 'EU Trust List Parse')
    .option('-m, --mozilla', 'Mozilla Trust List Parse')
    .option('-s, --microsoft', 'Microsoft Trust List Parse')
    .option('-f, --for [type]', 'Add the specified type for parse', 'ALL')
    .option('-o, --format [format]', 'Add the specified type for output format', 'pem');


program.on('--help', function () {
    console.log('  Examples:');
    console.log('');
    console.log('    $ tl-create --mozilla --format pem roots.pem');
    console.log('    $ tl-create --mozilla --for "EMAIL_PROTECTION,CODE_SIGNING" --format pem roots.pem');
    console.log('    $ tl-create --eutl --format pem roots.pem');
    console.log('    $ tl-create --eutl --format js roots.js');
    console.log('    $ tl-create --microsoft --format pem roots.pem');
    console.log('');
});

program.on('--help', function () {
    console.log('  Types:');
    console.log('');
    console.log('    DIGITAL_SIGNATURE');
    console.log('    NON_REPUDIATION');
    console.log('    KEY_ENCIPHERMENT');
    console.log('    DATA_ENCIPHERMENT');
    console.log('    KEY_AGREEMENT');
    console.log('    KEY_CERT_SIGN');
    console.log('    CRL_SIGN');
    console.log('    SERVER_AUTH');
    console.log('    CLIENT_AUTH');
    console.log('    CODE_SIGNING');
    console.log('    EMAIL_PROTECTION');
    console.log('    IPSEC_END_SYSTEM');
    console.log('    IPSEC_TUNNEL');
    console.log('    IPSEC_USER');
    console.log('    TIME_STAMPING');
    console.log('    STEP_UP_APPROVED');
    console.log('');
});

program.parse(process.argv);

function getRemoteTL(url) {
    console.log("TL data: Downloading from " + url);
    var res = request('GET', url, { 'timeout': 10000, 'retry': true, 'headers': { 'user-agent': 'nodejs' } });
    var data = res.body.toString('utf-8');
    console.log("TL data: Ok");
    return data;
}

function parseEUTL() {
    console.log("Trust Lists: EUTL");
    var data = getRemoteTL(euUrl);
    var eutl = new tl_create.EUTL();
    var tl = eutl.parse(data);
    eutl.TrustServiceStatusList.CheckSignature()
        .then(function (verify) {
            if (!verify)
                console.log("Warning!!!: EUTL signature is not valid");
            else
                console.log("Information: EUTL signature is valid");
        })
        .catch(function (e) {
            console.log("Error:", e.message);
        });
    return tl;
}

function parseMozilla() {
    console.log("Trust Lists: Mozilla");
    var data = getRemoteTL(mozillaUrl);
    var moz = new tl_create.Mozilla();
    var tl = moz.parse(data);
    return tl;
}

function parseMicrosoft() {
    console.log("Trust Lists: Microsoft");
    var res = request('GET', microsoftUrl, { 'timeout': 10000, 'retry': true, 'headers': { 'user-agent': 'nodejs' } });

    var dirpath = temp.mkdirSync('authrootstl');
    fs.writeFileSync(path.join(dirpath, 'authrootstl.cab'), res.body);
    if(process.platform === 'win32')
        child_process.execSync('expand authrootstl.cab .', { cwd: dirpath });
    else
        child_process.execSync('cabextract authrootstl.cab', { cwd: dirpath });
    var data = fs.readFileSync(path.join(dirpath, 'authroot.stl'), 'base64');
    //fs.writeFileSync('/tmp/llll.stl', data, 'binary');
    fs.unlinkSync(path.join(dirpath, 'authroot.stl'));
    fs.unlinkSync(path.join(dirpath, 'authrootstl.cab'));
    temp.cleanupSync();

    var ms = new tl_create.Microsoft();
    var tl = ms.parse(data);
    return tl;
}

function jsonToPKIJS(json) {
    var _pkijs = [];
    for (var i in json) {
        var raw = json[i].raw;
        if (raw)
            _pkijs.push(raw);
    }
    return _pkijs;
}

// prepare --for
var filter = program.for.split(",");

function trustFilter(item, index) {
    if (item.source === "EUTL")
        return true;
    for (var i in filter) {
        var f = filter[i];
        if (item.trust.indexOf(f) !== -1)
            return true;
    }
    return false;
}

if (!program.args.length) program.help();

else if (program.args[0]) {

    console.log('Parsing started: ' + getDateTime());
    var outputfile = program.args[0];

    var eutlTL, mozTL, msTL;

    if (program.eutl) {
        try {
            eutlTL = parseEUTL();
        } catch (e) {
            console.log(e.toString(), e.stack);
        }

    }
    if (program.mozilla) {
        try {
            mozTL = parseMozilla();
        } catch (e) {
            console.log(e.toString());
        }
    }
    if (program.microsoft) {
        try {
            msTL = parseMicrosoft();
        } catch (e) {
            console.log(e.toString());
        }
    }

    var tl = null;
    if (mozTL)
        tl = mozTL.concat(tl);
    if (eutlTL)
        tl = eutlTL.concat(tl);
    if (msTL)
        tl = msTL.concat(tl);

    // Filter data
    if (filter.indexOf("ALL") === -1) {
        console.log("Filter:");
        console.log("    Incoming data: " + tl.Certificates.length + " certificates");
        tl.filter(trustFilter);
        console.log("    Filtered data: " + tl.Certificates.length + " certificates");
    }

    switch ((program.format || "pem").toLowerCase()) {
        case "js":
            console.log("Output format: JS");
            fs.writeFileSync(outputfile, JSON.stringify(tl));
            break;
        case "pkijs":
            console.log("Output format: PKIJS");
            var _pkijs = jsonToPKIJS(tl.toJSON());
            fs.writeFileSync(outputfile, JSON.stringify(_pkijs));
            break;
        case "pem":
            console.log("Output format: PEM");
            fs.writeFileSync(outputfile, tl.toString());
            break;
        default:
            console.log("Invalid output format");
            break;
    }
}
