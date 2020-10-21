// Copyright (C) 2016-2017 Dmitry Chestnykh, Tony Arcieri
// MIT License. See LICENSE file for details.

import { IBlockCipher, ICryptoProvider, IMACLike } from "../interfaces";
import Block from "../internals/block";

/**
 * The AES-CMAC message authentication code
 */
export class CMAC implements IMACLike {
  /** Create a new CMAC instance from the given key */
  public static async importKey(provider: ICryptoProvider, keyData: Uint8Array): Promise<CMAC> {
    const cipher = await provider.importBlockCipherKey(keyData);

    // Generate subkeys.
    const subkey1 = new Block();
    await cipher.encryptBlock(subkey1);
    subkey1.dbl();

    const subkey2 = subkey1.clone();
    subkey2.dbl();

    return new CMAC(cipher, subkey1, subkey2);
  }

  private _buffer: Block;
  private _bufferPos = 0;
  private _finished = false;
  private _data_accum = new Array();

  constructor(
    private _cipher: IBlockCipher,
    private _subkey1: Block,
    private _subkey2: Block,
  ) {
    this._buffer = new Block();
  }

  public reset(): this {
    this._buffer.clear();
    this._bufferPos = 0;
    this._finished = false;
    this._data_accum = new Array();
    return this;
  }

  public clear() {
    this.reset();
    this._subkey1.clear();
    this._subkey2.clear();
  }

  public async update(data: Uint8Array): Promise<this> {
    this._data_accum.push(data);
    return this;
  }

  public async finish(): Promise<Uint8Array> {
    if (!this._finished) {
      // calculate total length and padding
      let totalLength = this._data_accum.reduce((acc, value) => acc + value.length, 0);
      let padding;
      if (totalLength === 0) {
        totalLength = padding = Block.SIZE;
      } else {
        padding = totalLength % Block.SIZE;
        if (padding > 0) {
          padding = Block.SIZE - padding;
          totalLength += padding;
        }
      }

      // construct single buffer with all data
      const allData = new Uint8Array(totalLength);
      let bufPos = 0;
      for (const data of this._data_accum) {
        allData.set(data, bufPos);
        bufPos += data.length;
      }

      // Select which subkey to use.
      const subkey = (padding > 0) ? this._subkey2 : this._subkey1;

      // XOR in the subkey.
      for (let i = 0 ; i < Block.SIZE ; ++i ) {
        allData[totalLength - Block.SIZE + i] ^= subkey.data[i];
      }

      // Pad if needed.
      if (padding > 0) {
        allData[totalLength - padding] ^= 0x80;
      }

      // Encrypt the full buffer to get the final digest.
      await this._cipher.encryptBlockBatch(this._buffer, allData);

      // Free the accumulation buffer and set finished flag.
      this._data_accum = new Array();
      this._finished = true;
    }

    return this._buffer.clone().data;
  }
}
