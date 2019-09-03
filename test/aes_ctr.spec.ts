// Copyright (C) 2016-2019 Dmitry Chestnykh, Tony Arcieri
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AesCtrExample } from "./support/test_vectors";

import SoftAes from "../src/providers/soft/aes";
import SoftAesCtr from "../src/providers/soft/aes_ctr";

@suite class SoftAesCtrSpec {
  static vectors: AesCtrExample[];

  static async before() {
    this.vectors = await AesCtrExample.loadAll();
  }

  @test async "passes the AES-CTR test vectors"() {
    for (let v of SoftAesCtrSpec.vectors) {
      const ctrSoft = new SoftAesCtr(new SoftAes(v.key));
      let ciphertext = await ctrSoft.encryptCtr(v.iv, v.plaintext);
      expect(ciphertext).to.eql(v.ciphertext);
    }
  }
}
