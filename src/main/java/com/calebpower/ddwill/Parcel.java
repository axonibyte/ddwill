package com.calebpower.ddwill;

import java.io.Serializable;
import java.util.Objects;

public class Parcel implements Serializable {

  private static final long serialVersionUID = 7023346193904515297L;
  
  private String custodian = null;
  private byte[] key = null;

  public Parcel(String custodian, byte[] key) {
    Objects.requireNonNull(custodian);
    Objects.requireNonNull(key);
    this.custodian = custodian;
    this.key = key.clone();
  }
  
  public String getCustodian() {
    return custodian;
  }
  
  public byte[] getKey() {
    return key.clone();
  }

}
