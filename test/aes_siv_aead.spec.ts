// Copyright (C) 2017-2019 Tony Arcieri
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";
import { AEADExample } from "./support/test_vectors";

import * as miscreant from "../src/index";

let expect = chai.expect;
chai.use(chaiAsPromised);

@suite class AEADSpec {
  static vectors: AEADExample[];

  static async before() {
    this.vectors = await AEADExample.loadAll();
  }

  @test async "should correctly seal and open with software cipher implementations"() {
    const softProvider = new miscreant.SoftCryptoProvider();

    for (let v of AEADSpec.vectors) {
      const aead = await miscreant.AEAD.importKey(v.key, v.alg, softProvider);
      const sealed = await aead.seal(v.plaintext, v.nonce, v.ad);
      expect(sealed).to.eql(v.ciphertext);

      const unsealed = await aead.open(sealed, v.nonce, v.ad);
      expect(unsealed).not.to.be.null;
      expect(unsealed!).to.eql(v.plaintext);
      expect(() => aead.clear()).not.to.throw();
    }
  }

  @test async "should not open with incorrect key"() {
    const softProvider = new miscreant.SoftCryptoProvider();

    for (let v of AEADSpec.vectors) {
      const badKey = v.key;
      badKey[0] ^= badKey[0];
      badKey[2] ^= badKey[2];
      badKey[3] ^= badKey[8];

      const aead = await miscreant.AEAD.importKey(badKey, v.alg, softProvider);
      await expect(aead.open(v.ciphertext, v.nonce, v.ad)).to.be.rejectedWith(miscreant.IntegrityError);
    }
  }

  @test async "should not open with incorrect associated data"() {
    const softProvider = new miscreant.SoftCryptoProvider();

    for (let v of AEADSpec.vectors) {
      const badAd = new Uint8Array(1);

      const aead = await miscreant.AEAD.importKey(v.key, v.alg, softProvider);
      await expect(aead.open(v.ciphertext, v.nonce, badAd)).to.be.rejectedWith(miscreant.IntegrityError);
    }
  }

  @test async "should not open with incorrect ciphertext"() {
    const softProvider = new miscreant.SoftCryptoProvider();

    for (let v of AEADSpec.vectors) {
      const badOutput = v.ciphertext;
      badOutput[0] ^= badOutput[0];
      badOutput[1] ^= badOutput[1];
      badOutput[3] ^= badOutput[8];

      const aead = await miscreant.AEAD.importKey(v.key, v.alg, softProvider);
      await expect(aead.open(badOutput, v.nonce, v.ad)).to.be.rejectedWith(miscreant.IntegrityError);
    }
  }
}
