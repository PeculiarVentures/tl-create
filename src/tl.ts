export interface X509Certificate {
  raw: string;
  operator?: string;
  trust?: string[];
  source?: string;
  evpolicy?: string[];
}

export declare type ExportX509CertificateJSON = X509Certificate[];

export class TrustedList {

  protected m_certificates: X509Certificate[] = [];

  get Certificates(): X509Certificate[] {
    return this.m_certificates;
  }

  AddCertificate(cert: X509Certificate): void {
    cert.raw = cert.raw.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s/g, "");

    if (cert.raw !== "") {
      const existing = this.m_certificates.find(c => c.raw === cert.raw);
      if (existing) {
        if (cert.trust) {
          if (!existing.trust) existing.trust = [];
          for (const t of cert.trust) {
            if (existing.trust.indexOf(t) === -1) existing.trust.push(t);
          }
        }
        if (cert.evpolicy) {
          if (!existing.evpolicy) existing.evpolicy = [];
          for (const p of cert.evpolicy) {
            if (existing.evpolicy.indexOf(p) === -1) existing.evpolicy.push(p);
          }
        }
        if (!existing.source && cert.source) existing.source = cert.source;
        if (!existing.operator && cert.operator) existing.operator = cert.operator;
        return;
      }
    }

    this.m_certificates.push(cert);
  }

  toJSON(): ExportX509CertificateJSON {
    let res: ExportX509CertificateJSON = [];

    for (let cert of this.Certificates)
      res.push(cert);

    return res;
  }

  concat(tl: TrustedList): TrustedList {
    if (tl)
      this.m_certificates = this.Certificates.concat(tl.Certificates);
    return this;
  }

  filter(callbackfn: (value: X509Certificate, index: number, array: X509Certificate[]) => boolean, thisArg?: any): TrustedList {
    this.m_certificates = this.Certificates.filter(callbackfn);
    return this;
  }

  toString(): string {
    let res: string[] = [];

    for (let cert of this.Certificates) {
      let pem = "";
      for (let i = 0, count = 0; i < cert.raw.length; i++, count++) {
        if (count > 63) {
          pem = `${pem}\r\n`;
          count = 0;
        }
        pem = pem + cert.raw[i];
      }
      res.push("Operator: " + cert.operator);
      res.push("Source: " + cert.source);
      if (cert.evpolicy?.length ?? 0 > 0)
        res.push("EV OIDs: " + cert.evpolicy?.join(", "));
      res.push("-----BEGIN CERTIFICATE-----");
      res.push(pem);
      res.push("-----END CERTIFICATE-----");
    }

    return res.join("\n");
  }
}
