package com.calebpower.ddwill;

import java.io.Serializable;
import java.util.Objects;

public class Parcel implements Comparable<Parcel>, Serializable {

  private static final long serialVersionUID = 7023346193904515297L;
  
  private String custodian = null;
  private byte[] key = null;
  private int ordinal;

  public Parcel(String custodian, byte[] key, int ordinal) {
    Objects.requireNonNull(custodian);
    Objects.requireNonNull(key);
    this.custodian = custodian;
    this.key = key.clone();
    this.ordinal = ordinal;
  }
  
  public String getCustodian() {
    return custodian;
  }
  
  public byte[] getKey() {
    return key.clone();
  }

  public int getOrdinal() {
    return ordinal;
  }

  @Override public int compareTo(Parcel parcel) {
    Objects.requireNonNull(parcel);
    return Integer.compare(ordinal, parcel.ordinal);
  }

}
