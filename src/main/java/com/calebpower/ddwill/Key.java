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
  
  private Key(String custodian, byte[] secret, byte[] iv) {
    try {
      
    } catch(IllegalArgumentException e) {
      
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
