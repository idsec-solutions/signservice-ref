package com.aaasec.sigserv.cssigapp.centralsig;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;

import java.security.SecureRandom;

/**
 * RSA-PSS as described in PKCS# 1 v 2.1.
 * <p>
 * Note: the usual value for the salt length is the number of
 * bytes in the hash function.
 */
public class PSSPadding {
  static final public byte TRAILER_IMPLICIT = (byte) 0xBC;

  private Digest contentDigest;
  private Digest mgfDigest;
  private SecureRandom random;

  private int modulusBits;
  private int hLen;
  private int mgfhLen;
  private boolean sSet;
  private int sLen;
  private int emBits;
  private byte[] salt;
  private byte[] mDash;
  private byte[] block;
  private byte trailer;

  /**
   * basic constructor
   * @param modulusBits number of bits in RSA key modulus
   * @param digest the digest to use.
   */
  public PSSPadding(
    int modulusBits,
    Digest digest) {
    this(modulusBits, digest, digest.getDigestSize() , TRAILER_IMPLICIT);
  }

  /**
   * basic constructor
   * @param modulusBits number of bits in RSA key modulus
   * @param digest the digest to use.
   * @param sLen   the length of the salt to use (in bytes).
   */
  public PSSPadding(
    int modulusBits,
    Digest digest,
    int sLen) {
    this(modulusBits, digest, sLen, TRAILER_IMPLICIT);
  }

  public PSSPadding(
    int modulusBits,
    Digest contentDigest,
    Digest mgfDigest,
    int sLen) {
    this(modulusBits, contentDigest, mgfDigest, sLen, TRAILER_IMPLICIT);
  }

  public PSSPadding(
    int modulusBits,
    Digest digest,
    int sLen,
    byte trailer) {
    this(modulusBits, digest, digest, sLen, trailer);
  }

  public PSSPadding(
    int modulusBits,
    Digest contentDigest,
    Digest mgfDigest,
    int sLen,
    byte trailer) {
    this.modulusBits = modulusBits;
    this.contentDigest = contentDigest;
    this.mgfDigest = mgfDigest;
    this.hLen = contentDigest.getDigestSize();
    this.mgfhLen = mgfDigest.getDigestSize();
    this.sSet = false;
    this.sLen = sLen;
    this.salt = new byte[sLen];
    this.mDash = new byte[8 + sLen + hLen];
    this.trailer = trailer;
    init();
  }

  public PSSPadding(
    int modulusBits,
    Digest digest,
    byte[] salt) {
    this(modulusBits, digest, digest, salt, TRAILER_IMPLICIT);
  }

  public PSSPadding(
    int modulusBits,
    Digest contentDigest,
    Digest mgfDigest,
    byte[] salt) {
    this(modulusBits, contentDigest, mgfDigest, salt, TRAILER_IMPLICIT);
  }

  public PSSPadding(
    int modulusBits,
    Digest contentDigest,
    Digest mgfDigest,
    byte[] salt,
    byte trailer) {
    this.modulusBits = modulusBits;
    this.contentDigest = contentDigest;
    this.mgfDigest = mgfDigest;
    this.hLen = contentDigest.getDigestSize();
    this.mgfhLen = mgfDigest.getDigestSize();
    this.sSet = true;
    this.sLen = salt.length;
    this.salt = salt;
    this.mDash = new byte[8 + sLen + hLen];
    this.trailer = trailer;
    init();
  }

  public void init() {

    random = CryptoServicesRegistrar.getSecureRandom();
    emBits = modulusBits - 1;

    if (emBits < (8 * hLen + 8 * sLen + 9)) {
      throw new IllegalArgumentException("key too small for specified hash and salt lengths");
    }

    block = new byte[(emBits + 7) / 8];

    reset();
  }

  /**
   * clear possible sensitive data
   */
  private void clearBlock(
    byte[] block) {
    for (int i = 0; i != block.length; i++) {
      block[i] = 0;
    }
  }

  /**
   * update the internal digest with the byte b
   */
  public void update(
    byte b) {
    contentDigest.update(b);
  }

  /**
   * update the internal digest with the byte array in
   */
  public void update( byte[] in) {
    contentDigest.update(in, 0, in.length);
  }

  /**
   * update the internal digest with the byte array in
   */
  public void update(
    byte[] in,
    int off,
    int len) {
    contentDigest.update(in, off, len);
  }

  /**
   * reset the internal state
   */
  public void reset() {
    contentDigest.reset();
  }

  /**
   * generate a signature for the message we've been loaded with using
   * the key we were initialised with.
   */
  public byte[] generateSignatureEncodedMessage()
    throws CryptoException, DataLengthException {
    contentDigest.doFinal(mDash, mDash.length - hLen - sLen);

    if (sLen != 0) {
      if (!sSet) {
        random.nextBytes(salt);
      }

      System.arraycopy(salt, 0, mDash, mDash.length - sLen, sLen);
    }

    byte[] h = new byte[hLen];

    contentDigest.update(mDash, 0, mDash.length);

    contentDigest.doFinal(h, 0);

    block[block.length - sLen - 1 - hLen - 1] = 0x01;
    System.arraycopy(salt, 0, block, block.length - sLen - hLen - 1, sLen);

    byte[] dbMask = maskGeneratorFunction1(h, 0, h.length, block.length - hLen - 1);
    for (int i = 0; i != dbMask.length; i++) {
      block[i] ^= dbMask[i];
    }

    block[0] &= (0xff >> ((block.length * 8) - emBits));

    System.arraycopy(h, 0, block, block.length - hLen - 1, hLen);

    block[block.length - 1] = trailer;

    byte[] b = new byte[block.length];
    System.arraycopy(block, 0, b, 0, block.length);

    clearBlock(block);

    return b;
  }

  /**
   * return true if the internal state represents the encodedMessage described
   * in the passed in array.
   */
  public boolean verifySignatureEncodedMessage(byte[] encodedMessage) {
    contentDigest.doFinal(mDash, mDash.length - hLen - sLen);

    try {
      System.arraycopy(encodedMessage, 0, block, block.length - encodedMessage.length, encodedMessage.length);
    }
    catch (Exception e) {
      return false;
    }

    if (block[block.length - 1] != trailer) {
      clearBlock(block);
      return false;
    }

    byte[] dbMask = maskGeneratorFunction1(block, block.length - hLen - 1, hLen, block.length - hLen - 1);

    for (int i = 0; i != dbMask.length; i++) {
      block[i] ^= dbMask[i];
    }

    block[0] &= (0xff >> ((block.length * 8) - emBits));

    for (int i = 0; i != block.length - hLen - sLen - 2; i++) {
      if (block[i] != 0) {
        clearBlock(block);
        return false;
      }
    }

    if (block[block.length - hLen - sLen - 2] != 0x01) {
      clearBlock(block);
      return false;
    }

    if (sSet) {
      System.arraycopy(salt, 0, mDash, mDash.length - sLen, sLen);
    }
    else {
      System.arraycopy(block, block.length - sLen - hLen - 1, mDash, mDash.length - sLen, sLen);
    }

    contentDigest.update(mDash, 0, mDash.length);
    contentDigest.doFinal(mDash, mDash.length - hLen);

    for (int i = block.length - hLen - 1, j = mDash.length - hLen;
         j != mDash.length; i++, j++) {
      if ((block[i] ^ mDash[j]) != 0) {
        clearBlock(mDash);
        clearBlock(block);
        return false;
      }
    }

    clearBlock(mDash);
    clearBlock(block);

    return true;
  }

  /**
   * int to octet string.
   */
  private void ItoOSP(
    int i,
    byte[] sp) {
    sp[0] = (byte) (i >>> 24);
    sp[1] = (byte) (i >>> 16);
    sp[2] = (byte) (i >>> 8);
    sp[3] = (byte) (i >>> 0);
  }

  /**
   * mask generator function, as described in PKCS1v2.
   */
  private byte[] maskGeneratorFunction1(
    byte[] Z,
    int zOff,
    int zLen,
    int length) {
    byte[] mask = new byte[length];
    byte[] hashBuf = new byte[mgfhLen];
    byte[] C = new byte[4];
    int counter = 0;

    mgfDigest.reset();

    while (counter < (length / mgfhLen)) {
      ItoOSP(counter, C);

      mgfDigest.update(Z, zOff, zLen);
      mgfDigest.update(C, 0, C.length);
      mgfDigest.doFinal(hashBuf, 0);

      System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mgfhLen);

      counter++;
    }

    if ((counter * mgfhLen) < length) {
      ItoOSP(counter, C);

      mgfDigest.update(Z, zOff, zLen);
      mgfDigest.update(C, 0, C.length);
      mgfDigest.doFinal(hashBuf, 0);

      System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mask.length - (counter * mgfhLen));
    }

    return mask;
  }
}
