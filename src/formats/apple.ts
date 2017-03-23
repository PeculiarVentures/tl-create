
namespace tl_create {

    const appleBaseURL = "https://opensource.apple.com/source/security_certificates/";

    interface IEVOID {
        [key: string]: string[];
    }

    export class Apple {

        getTrusted(datatllist?: string, datacertlist?: string, dataevroots?: string, skipfetch = false): TrustedList {
            let tl = new TrustedList();

            let tlVersion = this.getLatestVersion(datatllist);
            let certnames = this.getTrustedCertList(tlVersion, datacertlist);
            let evroots = this.getEVOIDList(tlVersion, dataevroots);

            if(skipfetch === false)
                process.stdout.write("Fetching certificates");
            for(let certname of certnames) {
                let certraw = "";
                let evpolicies: string[] = [];

                if(skipfetch === false)
                    process.stdout.write(".");

                if(skipfetch === false)
                    certraw = this.getTrustedCert(tlVersion, certname);
                if(certname in evroots)
                    evpolicies = evroots[certname];

                let tl_cert: X509Certificate = {
                    raw: certraw,
                    trust: [ "ANY" ],
                    operator: decodeURI(certname.slice(0, -4)),
                    source: "Apple",
                    evpolicy: evpolicies
                };

                tl.AddCertificate(tl_cert);
            }

            if(skipfetch === false)
                console.log();

            return tl;
        }

        getDisallowed(datatllist?: string, datadiscertlist?: string, skipfetch = false): TrustedList {
            let tl = new TrustedList();

            let tlVersion = this.getLatestVersion(datatllist);
            let certnames = this.getDistrustedCertList(tlVersion, datadiscertlist);

            if(skipfetch === false)
                process.stdout.write("Fetching certificates");
            for(let certname of certnames) {
                let certraw = "";
                let evpolicies: string[] = [];

                if(skipfetch === false)
                    process.stdout.write(".");

                if(skipfetch === false)
                    certraw = this.getDistrustedCert(tlVersion, certname);
                let tl_cert: X509Certificate = {
                    raw: certraw,
                    trust: [ "ANY" ],
                    operator: decodeURI(certname.slice(0, -4)),
                    source: "Apple",
                    evpolicy: evpolicies
                };

                tl.AddCertificate(tl_cert);
            }

            if(skipfetch === false)
                console.log();

            return tl;
        }

        getLatestVersion(data?: string): string {
            if(!data) {
                let res = request("GET", appleBaseURL, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
                data = res.body.toString();
            }
            let ch = cheerio.load(data);
            let verstr: string;
            let vernum = -1;

            ch("td").has("img").find("a").each(function(i, anchor) {
                let href = (<any>anchor.attribs)["href"];
                if(href.startsWith("security_certificates-")) {
                    let linkver = href.replace(/^security_certificates-/, "").replace(/\/*$/, "");
                    let linkarr = linkver.split(".");
                    let linknum = parseInt(linkarr[0]) * 1000000;
                    if(linkarr.length > 1)
                        linknum += parseInt(linkarr[1]) * 1000;
                    if(linkarr.length > 2)
                        linknum += parseInt(linkarr[2]);
                    if(linknum > vernum) {
                        verstr = linkver;
                        vernum = linknum;
                    }
                }
            });

            return verstr;
        }

        getTrustedCertList(version: string, data?: string): string[] {
            if(!data) {
                let url = appleBaseURL + "security_certificates-" + version + "/certificates/roots/";
                let res = request("GET", url, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
                data = res.body.toString();
            }
            let ch = cheerio.load(data);
            let filenames: string[] = [];

            ch("td").has("img").find("a").each(function(i, anchor) {
                let href = (<any>anchor.attribs)["href"];
                if(href.endsWith("/certificates/") || href.endsWith("/../") || (href === "AppleDEVID.cer"))
                    return;

                filenames.push(href);
            });

            return filenames;
        }

        getDistrustedCertList(version: string, data?: string): string[] {
            if(!data) {
                let url = appleBaseURL + "security_certificates-" + version + "/certificates/distrusted/";
                let res = request("GET", url, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
                data = res.body.toString();
            }
            let ch = cheerio.load(data);
            let filenames: string[] = [];

            ch("td").has("img").find("a").each(function(i, anchor) {
                let href = (<any>anchor.attribs)["href"];
                if(href.endsWith("/certificates/") || href.endsWith("/../"))
                    return;

                filenames.push(href);
            });

            return filenames;
        }

        getEVOIDList(version: string, data?: string): IEVOID {
            if(!data) {
                let url = appleBaseURL + "security_certificates-" + version + "/certificates/evroot.config?txt";
                let res = request("GET", url, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
                data = res.body.toString();
            }
            let evroots: IEVOID = {};

            let lines = data.split("\n").filter(function(v: string) { if((v === "") || (v.indexOf("#") === 0)) return false; else return true; });
            for(let line of lines) {
                let linespl = this.splitLine(line);
                for(let cert of linespl.splice(1)) {
                    cert = cert.replace(/"/g, "");
                    if(cert in evroots)
                        evroots[cert].push(linespl[0]);
                    else
                        evroots[cert] = [linespl[0]];
                }
            }

            return evroots;
        }

        getTrustedCert(version: string, filename: string): string {
            let url = appleBaseURL + "security_certificates-" + version + "/certificates/roots/" + filename;
            let res = request("GET", url, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
            return res.body.toString("base64");
        }

        getDistrustedCert(version: string, filename: string): string {
            let url = appleBaseURL + "security_certificates-" + version + "/certificates/distrusted/" + filename;
            let res = request("GET", url, { "timeout": 10000, "retry": true, "headers": { "user-agent": "nodejs" } });
            return res.body.toString("base64");
        }

        splitLine(line: string): string[] {
            let re_value = /(?!\s*$)\s*(?:'([^'\\]*(?:\\[\S\s][^'\\]*)*)'|"([^"\\]*(?:\\[\S\s][^"\\]*)*)"|([^ '"\s\\]*(?:\s+[^ '"\s\\]+)*))\s*(?: |$)/g;
            let a: string[] = [];
            line.replace(re_value, function(m0, m1, m2, m3) {
                if(m1 !== undefined) a.push(m1.replace(/\\'/g, "'"));
                else if(m2 !== undefined) a.push(m2.replace(/\\"/g, "\""));
                else if(m3 !== undefined) a.push(m3);
                return "";
            });
            return a;
        }
    }
}
