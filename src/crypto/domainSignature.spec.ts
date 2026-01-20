import {
    getSecureRandomBytes,
    KeyPair,
    keyPairFromSeed,
    sign,
} from "@ton/crypto";
import { domainSign, domainSignVerify } from "./domainSignature";
import { SignatureDomain } from "../types/SignatureDomain";

describe("domainSignature", () => {
    const data = Buffer.from("Hello world!");
    let keypair: KeyPair;
    let targetSignature: Buffer;

    beforeAll(async () => {
        const seed = await getSecureRandomBytes(32);
        keypair = keyPairFromSeed(seed);
        targetSignature = sign(data, keypair.secretKey);
    });

    it("should not break on empty domain", () => {
        const newSignature = domainSign({ data, secretKey: keypair.secretKey });
        expect(newSignature.equals(targetSignature)).toBe(true);
        expect(
            domainSignVerify({
                data,
                signature: newSignature,
                publicKey: keypair.publicKey,
            }),
        ).toBe(true);
    });

    it("should work with a domain", () => {
        const globalId = 123;
        const domain: SignatureDomain = { type: "l2", globalId };

        const newSignature = domainSign({
            data,
            secretKey: keypair.secretKey,
            domain,
        });
        expect(newSignature.equals(targetSignature)).toBe(false);
        expect(
            domainSignVerify({
                data,
                signature: newSignature,
                publicKey: keypair.publicKey,
                domain,
            }),
        ).toBe(true);
        expect(
            domainSignVerify({
                data,
                signature: targetSignature,
                publicKey: keypair.publicKey,
                domain,
            }),
        ).toBe(false);
        expect(
            domainSignVerify({
                data,
                signature: newSignature,
                publicKey: keypair.publicKey,
            }),
        ).toBe(false);
        expect(
            domainSignVerify({
                data,
                signature: targetSignature,
                publicKey: keypair.publicKey,
            }),
        ).toBe(true);
    });

    it("should handle negative global ids", () => {
        const globalId = -6001;
        const domain: SignatureDomain = { type: "l2", globalId };

        const newSignature = domainSign({
            data,
            secretKey: keypair.secretKey,
            domain,
        });
        expect(newSignature.equals(targetSignature)).toBe(false);
        expect(
            domainSignVerify({
                data,
                signature: newSignature,
                publicKey: keypair.publicKey,
                domain,
            }),
        ).toBe(true);
    });

    it("should be correct signature", () => {
        const globalId = 2000;
        const domain: SignatureDomain = { type: "l2", globalId };

        const seed = Buffer.from(
            "1e0ab9c5f92106c2055239dd319805cd928ab894a53dd2b2086bef2cc201c3a8",
            "hex",
        );

        const { secretKey, publicKey } = keyPairFromSeed(seed);
        const expectedSignature = Buffer.from(
            "335ff7f73e9be8d18ce4bc5c49be435cc442c27374b8323e2c3f5ac9b991f270256d7421e448e4a7e6b95751c1a807bc463d8742f14523736d021443ab630200",
            "hex",
        );
        const data = Buffer.from("Hello world!");
        const signature = domainSign({ data, secretKey, domain });

        expect(signature.equals(expectedSignature)).toBe(true);

        expect(domainSignVerify({ data, signature, domain, publicKey })).toBe(
            true,
        );
    });
});
