// Copyright (C) 2016-2017 Dmitry Chestnykh, Tony Arcieri
// MIT License. See LICENSE file for details.

import { IBlockCipher, ICryptoProvider, IMACLike } from "../interfaces";
import Block from "../internals/block";
import { xor } from "../internals/xor";

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
    return this;
  }

  public clear() {
    this.reset();
    this._subkey1.clear();
    this._subkey2.clear();
  }

  public async update(data: Uint8Array): Promise<this> {
    const left = Block.SIZE - this._bufferPos;
    let dataPos = 0;
    let dataLength = data.length;

    if (dataLength > left) {
      for (let i = 0; i < left; i++) {
        this._buffer.data[this._bufferPos + i] ^= data[i];
      }
      dataLength -= left;
      dataPos += left;
      await this._cipher.encryptBlock(this._buffer);
      this._bufferPos = 0;
    }

    if (dataLength > Block.SIZE) {
      const batchSize = Math.floor((dataLength - 1) / Block.SIZE);
      const fullBlockEndPos = dataPos + batchSize * Block.SIZE;
      const fwdBlock = data.slice(dataPos, fullBlockEndPos);
      dataLength -= batchSize * Block.SIZE;
      dataPos = fullBlockEndPos;

      await this._cipher.encryptBlockBatch(this._buffer, fwdBlock);
    }

    for (let i = 0; i < dataLength; i++) {
      this._buffer.data[this._bufferPos++] ^= data[dataPos + i];
    }

    return this;
  }

  public async finish(): Promise<Uint8Array> {
    if (!this._finished) {
      // Select which subkey to use.
      const subkey = (this._bufferPos < Block.SIZE) ? this._subkey2 : this._subkey1;

      // XOR in the subkey.
      xor(this._buffer.data, subkey.data);

      // Pad if needed.
      if (this._bufferPos < Block.SIZE) {
        this._buffer.data[this._bufferPos] ^= 0x80;
      }

      // Encrypt buffer to get the final digest.
      await this._cipher.encryptBlock(this._buffer);

      // Set finished flag.
      this._finished = true;
    }

    return this._buffer.clone().data;
  }
}
