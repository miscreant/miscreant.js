// Copyright (C) 2016-2019 Dmitry Chestnykh, Tony Arcieri
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AesCmacExample } from "./support/test_vectors";

import * as miscreant from "../src/index";

@suite class SoftAesCmacSpec {
  static vectors: AesCmacExample[];

  static async before() {
    this.vectors = await AesCmacExample.loadAll();
  }

  @test async "passes the AES-CMAC test vectors"() {
    const softProvider = new miscreant.SoftCryptoProvider();

    for (let v of SoftAesCmacSpec.vectors) {
      const mac = await miscreant.CMAC.importKey(softProvider, v.key);
      await mac.update(v.message);
      expect(await mac.finish()).to.eql(v.tag);
    }
  }
}
