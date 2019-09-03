import { IBlockCipher, ICryptoProvider, ICTRLike } from "../interfaces";
import SoftAes from "./soft/aes";
import SoftAesCtr from "./soft/aes_ctr";

/**
 * Pure JavaScript cryptography implementations
 *
 * WARNING: Not constant time! May leak keys or have other security issues.
 */
export class SoftCryptoProvider implements ICryptoProvider {
  constructor() {
    // This class doesn't do anything, it just signals that soft impls should be used
  }

  public async importBlockCipherKey(keyData: Uint8Array): Promise<IBlockCipher> {
    return new SoftAes(keyData);
  }

  public async importCTRKey(keyData: Uint8Array): Promise<ICTRLike> {
    return new SoftAesCtr(new SoftAes(keyData));
  }
}
