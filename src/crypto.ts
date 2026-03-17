import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import * as XmlDSigJs from "xmldsigjs";
import { Crypto } from "@peculiar/webcrypto";

export { asn1js, pkijs };

export const crypto = new Crypto();
const cryptoName = "@peculiar/webcrypto";
pkijs.setEngine(cryptoName, crypto, new pkijs.CryptoEngine({
  name: cryptoName,
  crypto: crypto,
  subtle: crypto.subtle
}));

export function registerXmlDsigAlgorithms(): void {
  XmlDSigJs.CryptoConfig.RegisterSignatureAlgorithm(XmlDSigJs.RSA_PSS_SHA1_NAMESPACE, XmlDSigJs.RsaPssWithoutParamsSha1 as any);
  XmlDSigJs.CryptoConfig.RegisterSignatureAlgorithm(XmlDSigJs.RSA_PSS_SHA256_NAMESPACE, XmlDSigJs.RsaPssWithoutParamsSha256 as any);
  XmlDSigJs.CryptoConfig.RegisterSignatureAlgorithm(XmlDSigJs.RSA_PSS_SHA384_NAMESPACE, XmlDSigJs.RsaPssWithoutParamsSha384 as any);
  XmlDSigJs.CryptoConfig.RegisterSignatureAlgorithm(XmlDSigJs.RSA_PSS_SHA512_NAMESPACE, XmlDSigJs.RsaPssWithoutParamsSha512 as any);
}

registerXmlDsigAlgorithms();
