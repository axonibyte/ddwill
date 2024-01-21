package com.calebpower.ddwill;

public class FloatingParcel extends Parcel {

  private static final long serialVersionUID = 1416061560769445023L;

  private byte[] ciphertext = null;
  private byte[][] fragments = null;
  private int floaterCount;

  public FloatingParcel(String custodian, byte[] key, byte[] ciphertext, byte[][] fragments, int floaterCount, int ordinal) {
    super(custodian, key, ordinal);
    this.ciphertext = ciphertext.clone();
    this.fragments = new byte[fragments.length][];
    for(int i = 0; i < fragments.length; i++)
      this.fragments[i] = fragments[i].clone();
    this.floaterCount = floaterCount;
  }

  public byte[] getCiphertext() {
    return ciphertext.clone();
  }

  public byte[][] getFragments() {
    byte[][] fragments = new byte[this.fragments.length][];
    for(int i = 0; i < fragments.length; i++)
      fragments[i] = this.fragments[i].clone();
    return fragments;
  }

  public int getFloaterCount() {
    return floaterCount;
  }
}
