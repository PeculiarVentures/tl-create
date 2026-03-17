import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { Crypto } from "@peculiar/webcrypto";

export { asn1js, pkijs };

export const crypto = new Crypto();
const cryptoName = "@peculiar/webcrypto";
pkijs.setEngine(cryptoName, crypto, new pkijs.CryptoEngine({
  name: cryptoName,
  crypto: crypto,
  subtle: crypto.subtle
}));
