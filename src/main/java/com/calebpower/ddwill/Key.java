package com.calebpower.ddwill;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Key {
  
  private static final int KEY_LENGTH = 256;
  
  private SecretKey key = null;
  private String custodian = null;
  
  public Key(String custodian) throws NoSuchAlgorithmException {
    this.custodian = custodian;
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(KEY_LENGTH);
    key = keyGenerator.generateKey();
    
  }
  
  public Key(String custodian, String secret) {
    this.custodian = custodian;
    this.key = new SecretKeySpec(Base64.getDecoder().decode(secret), "AES");
  }
  
  public String getCustodian() {
    return custodian;
  }
  
  public byte[] getSecretBytes() {
    return key.getEncoded();
  }
  
  public String getEncodedSecret() {
    return Base64.getEncoder().encodeToString(key.getEncoded());
  }
  
}
