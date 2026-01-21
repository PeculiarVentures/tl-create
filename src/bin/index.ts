#!/usr/bin/env node

import program from "commander";
import * as XAdES from "xadesjs";
import { DOMParser, XMLSerializer } from "xmldom";
import * as pvutils from "pvutils";
import * as nodeCrypto from "crypto";
import * as tl_create from "..";
import * as fs from "fs";
import * as path from "path";
import { crypto, pkijs, asn1js } from "../crypto";

(global as any)["DOMParser"] = DOMParser;
(global as any)["XMLSerializer"] = XMLSerializer;
XAdES.Application.setEngine("@peculiar/webcrypto", crypto);

/*
 * Utility functions
 */
function getDateTime() {

  let date = new Date();

  let hour = date.getHours();
  hour = +(hour < 10 ? "0" : "") + hour;

  let min = date.getMinutes();
  min = +(min < 10 ? "0" : "") + min;

  let sec = date.getSeconds();
  sec = +(sec < 10 ? "0" : "") + sec;

  let year = date.getFullYear();

  let month = date.getMonth() + 1;
  month = +(month < 10 ? "0" : "") + month;

  let day = date.getDate();
  day = +(day < 10 ? "0" : "") + day;

  return `${year}:${month}:${day}:${hour}:${min}:${sec}`;
}

program
  .version(require(path.join(__dirname, "../../../package.json")).version)
  .option("-e, --eutl", "EU Trust List Parse")
  .option("-m, --mozilla", "Mozilla Trust List Parse")
  .option("-s, --microsoft", "Microsoft Trust List Parse")
  .option("-a, --apple", "Apple Trust List Parse")
  .option("-c, --cisco", "Cisco Trust List Parse")
  .option("-A, --aatl", "Adobe Trust List Parse")
  .option("-C, --ciscotype [type]", "Select Cisco Trusted Root Store (external/union/core)", "external")
  .option("-f, --for [type]", "Add the specified type for parse", "ALL")
  .option("-o, --format [format]", "Add the specified type for output format", "pem")
  .option("-d, --disallowed", "Fetch disallowed roots instead of trusted");


program.on("--help", () => {
  console.log("  Examples:");
  console.log("");
  console.log("    $ tl-create --mozilla --format pem roots.pem");
  console.log("    $ tl-create --mozilla --for \"EMAIL_PROTECTION,CODE_SIGNING\" --format pem roots.pem");
  console.log("    $ tl-create --eutl --format pem roots.pem");
  console.log("    $ tl-create --eutl --format js roots.js");
  console.log("    $ tl-create --microsoft --format pem roots.pem");
  console.log("    $ tl-create --microsoft --disallowed --format pem disallowedroots.pem");
  console.log("    $ tl-create --apple --format pem roots.pem");
  console.log("    $ tl-create --cisco --ciscotype core --format pem roots.pem");
  console.log("    $ tl-create --aatl --format pem roots.pem");
  console.log("");
});

program.on("--help", () => {
  console.log("  Types:");
  console.log("");
  console.log("    DIGITAL_SIGNATURE");
  console.log("    NON_REPUDIATION");
  console.log("    KEY_ENCIPHERMENT");
  console.log("    DATA_ENCIPHERMENT");
  console.log("    KEY_AGREEMENT");
  console.log("    KEY_CERT_SIGN");
  console.log("    CRL_SIGN");
  console.log("    SERVER_AUTH");
  console.log("    CLIENT_AUTH");
  console.log("    CODE_SIGNING");
  console.log("    EMAIL_PROTECTION");
  console.log("    IPSEC_END_SYSTEM");
  console.log("    IPSEC_TUNNEL");
  console.log("    IPSEC_USER");
  console.log("    IPSEC_PROTECTION");
  console.log("    TIME_STAMPING");
  console.log("    STEP_UP_APPROVED");
  console.log("    OCSP_SIGNING");
  console.log("    DOCUMENT_SIGNING");
  console.log("    EFS_CRYPTO");
  console.log("");
});

program.parse(process.argv);

function parseEUTLTrusted() {
  console.log("Trust Lists: EUTL");

  let eutl = new tl_create.EUTL();
  let tl = eutl.getTrusted();

  Promise.all(eutl.TrustServiceStatusLists.map(function (list) { return list.CheckSignature(); }))
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

function parseEUTLDisallowed() {
  throw "EUTL does not support disallowed certificates.";
}

function parseMozillaTrusted() {
  console.log("Trust Lists: Mozilla");
  let moz = new tl_create.Mozilla();
  let tl = moz.getTrusted();
  return tl;
}

function parseMozillaDisallowed() {
  console.log("Trust Lists: Mozilla");
  let moz = new tl_create.Mozilla();
  let tl = moz.getDisallowed();
  return tl;
}

function parseMicrosoftTrusted() {
  console.log("Trust Lists: Microsoft");
  let ms = new tl_create.Microsoft();
  let tl = ms.getTrusted();
  return tl;
}

function parseMicrosoftDisallowed() {
  console.log("Trust Lists: Microsoft");
  let ms = new tl_create.Microsoft();
  let tl = ms.getDisallowed();
  return tl;
}

function parseAppleTrusted() {
  console.log("Trust Lists: Apple");
  let apple = new tl_create.Apple();
  let tl = apple.getTrusted();
  return tl;
}

function parseAppleDisallowed() {
  console.log("Trust Lists: Apple");
  let apple = new tl_create.Apple();
  let tl = apple.getDisallowed();
  return tl;
}

function parseCiscoTrusted(ciscoType: string) {
  console.log(`Trust Lists: Cisco - ${ciscoType}`);
  let cisco = new tl_create.Cisco(ciscoType);
  let tl = cisco.getTrusted();
  cisco.verifyP7()
    .then(function (verify) {
      if (!verify)
        console.log("Warning!!!: Cisco PKCS#7 signature verification failed");
      else
        console.log("Information: Cisco PKCS#7 signature verification successful");
    })
    .catch(function (e) {
      console.log("Error:", e);
    });
  return tl;
}

function parseCiscoDisallowed(): tl_create.TrustedList {
  throw new Error("Cisco does not support disallowed certificates.");
}

async function parseAATLTrusted() {
  console.log("Trust Lists: AATL");
  const adobe = new tl_create.AATL();
  const tl = await adobe.getTrusted();

  return tl;
}

function parseAATLDisallowed(): never {
  throw new Error("AATL temporary does not support disallowed certificates.");
}

function jsonToPKIJS(json: tl_create.X509Certificate[]) {
  let _pkijs = [];
  for (let i in json) {
    let raw = json[i].raw;
    if (raw)
      _pkijs.push(raw);
  }
  return _pkijs;
}

// prepare --for
let filter = program.for.split(",");

function trustFilter(item: tl_create.X509Certificate) {
  if (item.source === "EUTL")
    return true;
  if (item.trust!.indexOf("ANY") !== -1)
    return true;
  for (let i in filter) {
    let f = filter[i];
    if (item.trust!.indexOf(f) !== -1)
      return true;
  }
  return false;
}

if (!program.args.length) {
  if (program.format !== "files") {
    program.help();
  }
}

console.log("Parsing started: " + getDateTime());
let outputFile = program.args[0];

async function main() {
  let eutlTL: tl_create.TrustedList | undefined;
  let mozTL: tl_create.TrustedList | undefined;
  let msTL: tl_create.TrustedList | undefined;
  let appleTL: tl_create.TrustedList | undefined;
  let adobeTL: tl_create.TrustedList | undefined;
  let ciscoTL: tl_create.TrustedList | undefined;

  if (program.eutl) {
    try {
      if (!program.disallowed)
        eutlTL = parseEUTLTrusted();
      else
        eutlTL = parseEUTLDisallowed() as any;
    } catch (e: any) {
      if (e.stack)
        console.log(e.toString(), e.stack);
      else
        console.log(e.toString());
    }

  }
  if (program.mozilla) {
    try {
      if (!program.disallowed)
        mozTL = parseMozillaTrusted();
      else
        mozTL = parseMozillaDisallowed();
    } catch (e: any) {
      console.log(e.toString());
    }
  }
  if (program.microsoft) {
    try {
      if (!program.disallowed)
        msTL = parseMicrosoftTrusted();
      else
        msTL = parseMicrosoftDisallowed();
    } catch (e: any) {
      console.log(e.toString());
    }
  }
  if (program.apple) {
    try {
      if (!program.disallowed)
        appleTL = parseAppleTrusted();
      else
        appleTL = parseAppleDisallowed();
    } catch (e: any) {
      console.log(e.toString());
    }
  }
  if (program.cisco) {
    try {
      if (!program.disallowed)
        ciscoTL = parseCiscoTrusted(program.ciscotype);
      else
        ciscoTL = parseCiscoDisallowed();
    } catch (e: any) {
      console.log(e.toString());
    }
  }
  if (program.aatl) {
    try {
      if (!program.disallowed)
        adobeTL = await parseAATLTrusted();
      else
        adobeTL = parseAATLDisallowed();
    } catch (e: any) {
      console.log(e);
    }
  }

  let tl = new tl_create.TrustedList();
  if (mozTL)
    tl = mozTL.concat(tl);
  if (eutlTL)
    tl = eutlTL.concat(tl);
  if (msTL)
    tl = msTL.concat(tl);
  if (appleTL)
    tl = appleTL.concat(tl);
  if (ciscoTL)
    tl = ciscoTL.concat(tl);
  if (adobeTL)
    tl = adobeTL.concat(tl);

  if (tl === null) {
    console.log("Cannot fetch any Trust Lists.");
    process.exit(1);
  }

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
      fs.writeFileSync(outputFile, JSON.stringify(tl), { flag: "w+" });
      break;
    case "pkijs":
      console.log("Output format: PKIJS");
      let _pkijs = jsonToPKIJS(tl.toJSON());
      fs.writeFileSync(outputFile, JSON.stringify(_pkijs), { flag: "w+" });
      break;
    case "pem":
      console.log("Output format: PEM");
      fs.writeFileSync(outputFile, tl.toString(), { flag: "w+" });
      break;
    case "files": {
        const crypto = pkijs.getCrypto();
        if (typeof crypto === "undefined") {
          console.log("Unable to initialize cryptographic engine");
          break;
        }

        let filesJSON: Record<string, Record<string, string>[]> = {};

        function storeFiles(directory: string, trustList: tl_create.TrustedList) {
          let targetDir = `./roots/${directory}`;

          filesJSON[directory] = [];

          let PKICertificate = pkijs.Certificate;

          let files = [];
          let noIdFiles = [];

          for (let i = 0; i < trustList.Certificates.length; i++) {
            let fileRaw = pvutils.stringToArrayBuffer(pvutils.fromBase64(trustList.Certificates[i].raw));

            let asn1 = asn1js.fromBER(fileRaw);
            if (asn1.offset === (-1))
              continue;

            let certificate;

            try {
              certificate = new PKICertificate({ schema: asn1.result });
            }
            catch (ex: any) {
              continue;
            }

            // certificate.subject.valueBeforeDecode
            let nameID = nodeCrypto.createHash("SHA1").update(Buffer.from(certificate.subject.valueBeforeDecode)).digest().toString("hex").toUpperCase();

            if ("extensions" in certificate) {
              for (let j = 0; j < certificate.extensions.length; j++) {
                if (certificate.extensions[j].extnID === "2.5.29.14") {
                  files.push({
                    name: pvutils.bufferToHexCodes(certificate.extensions[j].parsedValue.valueBlock.valueHex),
                    nameID: nameID,
                    content: fileRaw.slice(0)
                  });

                  break;
                }

                noIdFiles.push({
                  publicKey: certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex.slice(0),
                  nameID: nameID,
                  content: fileRaw.slice(0)
                });
              }
            }
          }

          if ((files.length) || (noIdFiles.length)) {
            if (!fs.existsSync(targetDir))
              fs.mkdirSync(targetDir);
          }

          if (files.length) {
            for (let k = 0; k < files.length; k++) {
              filesJSON[directory].push({
                k: files[k].name,
                n: files[k].nameID
              });

              // TODO: temporary workaround issue with mozilla cert
              try {
                fs.writeFileSync(targetDir + "/" + files[k].name, Buffer.from(files[k].content));

                filesJSON[directory].push({
                  k: files[k].name,
                  n: files[k].nameID
                });
              } catch (err: any) {
                if (err.code !== "ENAMETOOLONG") {
                  throw err;
                }
                console.log(err.message);
              }
            }

            if (noIdFiles.length) {
              for (let m = 0; m < noIdFiles.length; m++) {
                let keyID = nodeCrypto.createHash("SHA1").update(Buffer.from(noIdFiles[m].publicKey)).digest().toString("hex").toUpperCase();

                filesJSON[directory].push({
                  k: keyID,
                  n: noIdFiles[m].nameID
                });

                fs.writeFileSync(targetDir + "/" + keyID, Buffer.from(noIdFiles[m].content));
              }
            }

            fs.writeFileSync("./roots/index.json", Buffer.from(JSON.stringify(filesJSON)));
          }
        }

        if (!fs.existsSync("./roots"))
          fs.mkdirSync("./roots");

        if (mozTL)
          storeFiles("mozilla", mozTL);

        if (eutlTL)
          storeFiles("eutl", eutlTL);

        if (msTL)
          storeFiles("microsoft", msTL);

        if (appleTL)
          storeFiles("apple", appleTL);

        if (ciscoTL)
          storeFiles("cisco", ciscoTL);

        if (adobeTL)
          storeFiles("aatl", adobeTL);

        break;
      }
    default:
      console.log("Invalid output format");
      break;
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Failed with error:", error);
    process.exit(1);
  });
