import fetch from "node-fetch";
import cheerio from "cheerio";
import { TrustedList, X509Certificate } from "../tl";

interface IEVOID {
  [key: string]: string[];
}

export interface AppleParameters {
  url?: string;
  timeout?: number;
}

export class Apple {

  public static URL = "https://opensource.apple.com/source/security_certificates/";
  public static TIMEOUT = 1e4;

  public url: string;
  public timeout: number;

  constructor({
    url = Apple.URL,
    timeout = Apple.TIMEOUT,
  }: AppleParameters = {}) {
    this.url = url;
    this.timeout = timeout;
  }

  async getTrusted(dataTlList?: string, dataCertList?: string, dataEvRoots?: string, skipFetch = false): Promise<TrustedList> {
    let tl = new TrustedList();

    let tlVersion = await this.getLatestVersion(dataTlList);
    let certNames = await this.getTrustedCertList(tlVersion, dataCertList);
    let evRoots = await this.getEVOIDList(tlVersion, dataEvRoots);

    if (skipFetch === false)
      process.stdout.write("Fetching certificates");
    for (let certName of certNames) {
      let certRaw = "";
      let evPolicies: string[] = [];

      if (skipFetch === false)
        process.stdout.write(".");

      if (skipFetch === false)
        certRaw = await this.getTrustedCert(tlVersion, certName);
      if (certName in evRoots)
        evPolicies = evRoots[certName];

      let tl_cert: X509Certificate = {
        raw: certRaw,
        trust: ["ANY"],
        operator: decodeURI(certName.slice(0, -4)),
        source: "Apple",
        evpolicy: evPolicies
      };

      tl.AddCertificate(tl_cert);
    }

    if (skipFetch === false)
      console.log();

    return tl;
  }

  async getDisallowed(dataTlList?: string, dataDisCertList?: string, skipFetch = false): Promise<TrustedList> {
    let tl = new TrustedList();

    let tlVersion = await this.getLatestVersion(dataTlList);
    let certNames = await this.getDistrustedCertList(tlVersion, dataDisCertList);

    if (skipFetch === false)
      process.stdout.write("Fetching certificates");
    for (let certName of certNames) {
      let certRaw = "";
      let evPolicies: string[] = [];

      if (skipFetch === false)
        process.stdout.write(".");

      if (skipFetch === false)
        certRaw = await this.getDistrustedCert(tlVersion, certName);
      let tl_cert: X509Certificate = {
        raw: certRaw,
        trust: ["ANY"],
        operator: decodeURI(certName.slice(0, -4)),
        source: "Apple",
        evpolicy: evPolicies
      };

      tl.AddCertificate(tl_cert);
    }

    if (skipFetch === false)
      console.log();

    return tl;
  }

  async getLatestVersion(data: string = ""): Promise<string> {
    if (!data) {
      const res = await fetch(this.url, { "method": "GET", timeout: this.timeout, "headers": { "user-agent": "node-fetch (nodejs)" } });
      data = await res.text();
    }
    let ch = cheerio.load(data);
    let verStr: string = "";
    let verNum = -1;

    ch("td").has("img").find("a").each((i, anchor) => {
      let href = (anchor as cheerio.TagElement).attribs["href"];
      if (href.startsWith("security_certificates-")) {
        let linkVer = href.replace(/^security_certificates-/, "").replace(/\/*$/, "");
        let linkArr = linkVer.split(".");
        let linkNum = parseInt(linkArr[0]) * 1000000;
        if (linkArr.length > 1)
          linkNum += parseInt(linkArr[1]) * 1000;
        if (linkArr.length > 2)
          linkNum += parseInt(linkArr[2]);
        if (linkNum > verNum) {
          verStr = linkVer;
          verNum = linkNum;
        }
      }
    });

    return verStr;
  }

  async getTrustedCertList(version: string, data: string = ""): Promise<string[]> {
    if (!data) {
      const url = this.url + "security_certificates-" + version + "/certificates/roots/";
      const res = await fetch(url, { method: "GET", timeout: this.timeout, headers: { "user-agent": "node-fetch (nodejs)" } });
      data = await res.text();
    }
    let ch = cheerio.load(data);
    let filenames: string[] = [];

    ch("td").has("img").find("a").each(function (i, anchor) {
      let href = (anchor as cheerio.TagElement).attribs["href"];
      if (href.endsWith("/certificates/") || href.endsWith("/../") || (href === "AppleDEVID.cer"))
        return;

      filenames.push(href);
    });

    return filenames;
  }

  async getDistrustedCertList(version: string, data: string = ""): Promise<string[]> {
    if (!data) {
      const url = this.url + "security_certificates-" + version + "/certificates/distrusted/";
      const res = await fetch(url, { method: "GET", timeout: this.timeout, headers: { "user-agent": "node-fetch (nodejs)" } });
      data = await res.text();
    }
    let ch = cheerio.load(data);
    let filenames: string[] = [];

    ch("td").has("img").find("a").each(function (i, anchor) {
      let href = (anchor as cheerio.TagElement).attribs["href"];
      if (href.endsWith("/certificates/") || href.endsWith("/../"))
        return;

      filenames.push(href);
    });

    return filenames;
  }

  async getEVOIDList(version: string, data: string = ""): Promise<IEVOID> {
    if (!data) {
      const url = this.url + "security_certificates-" + version + "/certificates/evroot.config?txt";
      const res = await fetch(url, { method: "GET", timeout: this.timeout, headers: { "user-agent": "node-fetch (nodejs)" } });
      data = await res.text();
    }
    let evRoots: IEVOID = {};

    let lines = data.split("\n").filter((v: string) => { if ((v === "") || (v.indexOf("#") === 0)) return false; else return true; });
    for (let line of lines) {
      let lineSpl = this.splitLine(line);
      for (let cert of lineSpl.splice(1)) {
        cert = cert.replace(/"/g, "");
        if (cert in evRoots)
          evRoots[cert].push(lineSpl[0]);
        else
          evRoots[cert] = [lineSpl[0]];
      }
    }

    return evRoots;
  }

  async getTrustedCert(version: string, filename: string): Promise<string> {
    const url = this.url + "security_certificates-" + version + "/certificates/roots/" + filename;
    const res = await fetch(url, { method: "GET", timeout: this.timeout, headers: { "user-agent": "node-fetch (nodejs)" } });
    return Buffer.from(await res.arrayBuffer()).toString("base64");
  }

  async getDistrustedCert(version: string, filename: string): Promise<string> {
    const url = this.url + "security_certificates-" + version + "/certificates/distrusted/" + filename;
    const res = await fetch(url, { method: "GET", timeout: this.timeout, headers: { "user-agent": "node-fetch (nodejs)" } });
    return Buffer.from(await res.arrayBuffer()).toString("base64");
  }

  splitLine(line: string): string[] {
    let re_value = /(?!\s*$)\s*(?:'([^'\\]*(?:\\[\S\s][^'\\]*)*)'|"([^"\\]*(?:\\[\S\s][^"\\]*)*)"|([^ '"\s\\]*(?:\s+[^ '"\s\\]+)*))\s*(?: |$)/g;
    let a: string[] = [];
    line.replace(re_value, function (m0, m1, m2, m3) {
      if (m1 !== undefined) a.push(m1.replace(/\\'/g, "'"));
      else if (m2 !== undefined) a.push(m2.replace(/\\"/g, "\""));
      else if (m3 !== undefined) a.push(m3);
      return "";
    });
    return a;
  }
}
