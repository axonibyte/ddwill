package com.calebpower.ddwill;

import java.io.Serializable;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.util.Arrays;

/**
 * Wrapper for a fragment of a datum.
 * 
 * @author Caleb L. Power
 */
public class Fragment implements Serializable {
  private static final long serialVersionUID = 6443507277522053121L;

  /**
   * Splits a byte array into an array of bytes, byte-by-byte in a
   * round-robin fashion. The elements of the resulting array will be ordered
   * by length in a descending (but not strictly descending) order.
   * 
   * @param whole the original byte array
   * @param parts the number of fragments to return
   * @return an array of Fragment objects, each defining a fragment of the whole
   * @throws BadFragReqException iff the specified parameters would otherwise
   *         make the operation fail
   */
  public static Fragment[] split(byte[] whole, int parts) throws BadFragReqException {
    if(whole == null) throw new BadFragReqException("Cannot split a null array");
    if(parts < 1) throw new BadFragReqException("Cannot split into < 1 parts");
    
    int minFragSize = whole.length / parts;
    int bigFrags = whole.length % parts;
    
    byte[][] stagByteArr = new byte[parts][];
    for(int i = 0; i < parts; i++)
      stagByteArr[i] = new byte[i < bigFrags ? minFragSize + 1 : minFragSize];
    
    for(int i = 0; i < whole.length; i++)
      stagByteArr[i % parts][i / parts] = whole[i];
    
    Fragment[] frags = new Fragment[parts];
    for(int i = 0; i < parts; i++)
      frags[i] = new Fragment(stagByteArr[i]);
    
    return frags;
  }
  
  /**
   * Joins an array of fragments into a single byte array by picking bytes in
   * order in a round-robin fashion. The elements of the submitted array must
   * be provided such that they are ordered by length in a descending (but not
   * strictly descending) fashion. Furthermore, no two elements in the array
   * may have a difference in lengths exceeding two (2).
   * 
   * @param fragments the fragments that are to be joined
   * @return a byte array representing the joined fragments
   * @throws BadFragReqException iff the specified parameters would otherwise
   *         make the operation fail
   */
  public static byte[] join(Fragment[] fragments) throws BadFragReqException {
    if(fragments == null) throw new BadFragReqException("Cannot join a null array");
    
    int min = Integer.MAX_VALUE, max = 0, last = Integer.MAX_VALUE, total = 0;
    for(var f : fragments) {
      if(null == f) throw new BadFragReqException("Cannot merge a null file");
      total += f.bytes.length;
      if(f.bytes.length > last) throw new BadFragReqException("Cannot merge when arr[i] < arr[i - 1]");
      if(f.bytes.length < min) min = f.bytes.length;
      if(f.bytes.length > max) max = f.bytes.length;
      last = f.bytes.length;
    }
    if(max > min + 2) throw new BadFragReqException("Cannot merge when maxArr.size > minArr.size + 1");
    
    byte[] bytes = new byte[total];
    for(int i = 0; i < total; i++) {
      bytes[i] = fragments[i % fragments.length].bytes[i / fragments.length];
    }
    
    return bytes;
  }
  
  private byte[] bytes = null;
  
  /**
   * Instantiates a fragment with a set of bytes preloaded. Bytes are copied,
   * so subsequent mutation of the byte array will not affect the datum
   * associated with this fragment.
   * 
   * @param bytes the byte representation of the fragment
   */
  public Fragment(byte[] bytes) {
    this.bytes = Arrays.copyOf(bytes, bytes.length);
  }
  
  /**
   * Copy constructor.
   * 
   * @param fragment the fragment to copy
   */
  public Fragment(Fragment fragment) {
    this(fragment.bytes);
  }
  
  /**
   * Retrieves the raw bytes associated with this fragment. Mutation of the
   * returned array will not mutate the datum associated with this fragment.
   * 
   * @return an array of bytes denoting the value of the fragment
   */
  public byte[] getBytes() {
    return Arrays.copyOf(bytes, bytes.length);
  }
  
  /**
   * Encrypts the datum in-place with a secret key and initialization vector.
   * 
   * @param key the secret key
   */
  public void encrypt(Key key) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      SecretKeySpec keySpec = new SecretKeySpec(key.getSecretBytes(), "AES");
      GCMParameterSpec gcmPSpec = new GCMParameterSpec(128, key.getIV());
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmPSpec);
      bytes = cipher.doFinal(bytes);
    } catch(BadPaddingException
        | NoSuchAlgorithmException
        | NoSuchPaddingException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | IllegalBlockSizeException e) {
      throw new CryptOpRuntimeException(e);
    }
  }
  
  /**
   * Decrypts the datum in-place with a secret key and initialization vector.
   * 
   * @param key the secret key
   */
  public void decrypt(Key key) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      SecretKeySpec keySpec = new SecretKeySpec(key.getSecretBytes(), "AES");
      GCMParameterSpec gcmPSpec = new GCMParameterSpec(128, key.getIV());
      cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmPSpec);
      bytes = cipher.doFinal(bytes);
    } catch(BadPaddingException
        | NoSuchAlgorithmException
        | NoSuchPaddingException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | IllegalBlockSizeException e) {
      throw new CryptOpRuntimeException(e);
    }
  }

  /**
   * Appends a SHA3-512 hash to the end of the data. This inherently mutates
   * this fragment, and future encryption or decryption will apply to the whole.
   * The size of the modified data will be 64 bytes longer than the original.
   */
  public void applyHash() {
    try {
      final DigestSHA3 md = new DigestSHA3(512);
      md.update(bytes);
      byte[] buf = new byte[bytes.length + 64];
      System.arraycopy(bytes, 0, buf, 0, bytes.length);
      md.digest(buf, bytes.length, 64);
      bytes = buf;
    } catch(DigestException e) {
      throw new CryptOpRuntimeException(e);
    }
  }

  /**
   * Assumes that a SHA3-512 hash has been applied to the underlying data, and
   * attempts to match it with the rest of the data.
   *
   * @return true iff the provided hash matches that which results when hasing
   *         the rest of the data
   */
  public boolean verifyHash() {
    if(64 <= bytes.length) {
      final DigestSHA3 md = new DigestSHA3(512);
      md.update(bytes, 0, bytes.length - 64);
      byte[] digest = md.digest();
      for(int i = 0; i < 64; i++)
        if(bytes[bytes.length - 64 + i] != digest[i])
          return false;
      return true;
    }

    return false;
  }

  /**
   * Assumes that a SHA3-512 hash has been applied to the underlying data and
   * strips it. If successful, the modified data will be truncated by 64 bytes.
   */
  public void stripHash() {
    if(64 > bytes.length)
      throw new CryptOpRuntimeException(
          new IllegalStateException("hash not previously applied"));
    byte[] buf = new byte[bytes.length - 64];
    System.arraycopy(bytes, 0, buf, 0, bytes.length - 64);
    bytes = buf;
  }
  
  /**
   * An exception to be thrown if preflight checks fail before some operation
   * is to be carried out on one or more fragments.
   * 
   * @author Caleb L. Power
   */
  public final static class BadFragReqException extends Exception {
    private static final long serialVersionUID = 6116777127523539547L;

    /**
     * Instantiates the BadFragReqException with a message.
     * 
     * @param message the note to accompany the exception
     */
    public BadFragReqException(String message) {
      super(message);
    }
  }
  
}
