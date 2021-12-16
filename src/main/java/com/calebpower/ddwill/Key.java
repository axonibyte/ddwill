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
  
  public Key(String custodian) {
    try {
      this.iv = new byte[12];
      SecureRandom csprng = new SecureRandom();
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
  
  public String getCustodian() {
    return custodian;
  }
  
  public byte[] getIV() {
    return iv;
  }
  
  public byte[] getSecretBytes() {
    return key.getEncoded();
  }
  
  public String getEncodedSecret() {
    return Base64.getEncoder().encodeToString(key.getEncoded());
  }
  
}
