export const asn1js = require("asn1js");
export const pkijs = require("pkijs");
import { Crypto } from "@peculiar/webcrypto";

export const crypto = new Crypto();
const cryptoName = "@peculiar/webcrypto";
pkijs.setEngine(cryptoName, crypto, new pkijs.CryptoEngine({
  name: cryptoName,
  crypto: crypto,
  subtle: crypto.subtle
}));
