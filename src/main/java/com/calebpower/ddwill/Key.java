package com.calebpower.ddwill;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Key {
  
  private static final int KEY_LENGTH = 256;
  
  private SecretKey key = null;
  private String custodian = null;
  private byte[] iv = null;
  
  public static Key merge(Key[] keys) {
    int maxKeyBytes = 0, maxIVBytes = 0;
    byte[][] keyBytes = new byte[keys.length][];
    byte[][] ivBytes = new byte[keys.length][];
    for(int i = 0; i < keys.length; i++) {
      keyBytes[i] = keys[i].getSecretBytes();
      ivBytes[i] = keys[i].iv;
      if(keyBytes[i].length > maxKeyBytes) maxKeyBytes = keyBytes[i].length;
      if(ivBytes[i].length > maxIVBytes) maxIVBytes = ivBytes[i].length;
    }
    
    byte[] keyCombo = new byte[maxKeyBytes];
    byte[] ivCombo = new byte[maxIVBytes];
    
    for(int i = 0; i < keys.length; i++) {
      for(int j = 0; j < keyBytes[i].length; j++)
        keyCombo[j] = (byte)((i == 0) ? keyBytes[i][j] : (keyCombo[j] ^ keyBytes[i][j]));
      for(int j = 0; j < ivBytes[i].length; j++)
        ivCombo[j] = (byte)((i == 0) ? ivBytes[i][j] : (ivCombo[j] ^ ivBytes[i][j]));
    }
    
    Key key = new Key(null);
    key.iv = ivCombo;
    key.key = new SecretKeySpec(keyCombo, "AES");
    
    return key;
  }
  
  public Key(String custodian) {
    try {
      this.iv = new byte[12];
      SecureRandom csprng = SecureRandom.getInstanceStrong();
      csprng.nextBytes(this.iv);
      
      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      keyGenerator.init(KEY_LENGTH);
      this.key = keyGenerator.generateKey();
      
      this.custodian = custodian;
    } catch(NoSuchAlgorithmException e) {
      throw new CryptOpRuntimeException(e);
    }
  }
  
  public Key(String custodian, String secret, String iv) {
    try {
      this.iv = Base64.getDecoder().decode(iv);
      this.key = new SecretKeySpec(Base64.getDecoder().decode(secret), "AES");
      this.custodian = custodian;
    } catch(IllegalArgumentException e) {
      throw new CryptOpRuntimeException(e);
    }
  }

  public Key(String custodian, byte[] aggregated) {
    try {
      if(12 >= aggregated.length)
        throw new IllegalArgumentException("key too short");

      this.iv = new byte[12];
      System.arraycopy(
          aggregated,
          aggregated.length - 12,
          this.iv,
          0,
          12);

      byte[] key = new byte[aggregated.length - 12];
      System.arraycopy(
          aggregated,
          0,
          key,
          0,
          aggregated.length - 12);

      this.key = new SecretKeySpec(key, "AES");
      
    } catch(IllegalArgumentException e) {
      throw new CryptOpRuntimeException(e);
    }
  }
  
  public String getCustodian() {
    return custodian;
  }
  
  public byte[] getIV() {
    return iv;
  }
  
  public byte[] getSecretBytes() {
    return key.getEncoded();
  }

  public byte[] getAggregated() {
    byte[] buf = new byte[key.getEncoded().length + iv.length];
    System.arraycopy(
        key.getEncoded(),
        0,
        buf,
        0,
        key.getEncoded().length);
    System.arraycopy(
        iv,
        0,
        buf,
        key.getEncoded().length,
        iv.length);
    return buf;
  }
  
}
