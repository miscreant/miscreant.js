// Copyright (C) 2016-2019 Dmitry Chestnykh, Tony Arcieri
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AesPmacExample } from "./support/test_vectors";

import * as miscreant from "../src/index";

@suite class SoftAesPmacSpec {
  static vectors: AesPmacExample[];

  static async before() {
    this.vectors = await AesPmacExample.loadAll();
  }

  @test async "passes the AES-PMAC test vectors"() {
    const softProvider = new miscreant.SoftCryptoProvider();

    for (let v of SoftAesPmacSpec.vectors) {
      const mac = await miscreant.PMAC.importKey(softProvider, v.key);
      await mac.update(v.message);
      expect(v.tag).to.eql(await mac.finish());
    }
  }
}
