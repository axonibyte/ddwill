package com.calebpower.ddwill;

import org.json.JSONException;
import org.json.JSONObject;

public class Parcel {
  
  private static enum Param {
    CUSTODIAN,
    IV,
    KEY,
    PRECIOUS;
    
    @Override public String toString() {
      return name().toLowerCase();
    }
  }
  
  private String custodian = null;
  private String iv = null;
  private String key = null;
  private String precious = null; // my... PRECIOUSSSS!!!!!
  
  public Parcel(String custodian, String key, String iv, String precious) {
    this.custodian = custodian;
    this.iv = iv;
    this.key = key;
    this.precious = precious;
  }
  
  public Parcel(JSONObject jso) throws JSONException {
    this(
        jso.getString(Param.CUSTODIAN.toString()),
        jso.getString(Param.IV.toString()),
        jso.getString(Param.KEY.toString()),
        jso.getString(Param.PRECIOUS.toString()));
  }
  
  public JSONObject serialize() {
    return new JSONObject()
        .put(Param.CUSTODIAN.toString(), custodian)
        .put(Param.IV.toString(), iv)
        .put(Param.KEY.toString(), key)
        .put(Param.PRECIOUS.toString(), precious);
  }
  
  public String getCustodian() {
    return custodian;
  }
  
  public String getIV() {
    return iv;
  }
  
  public String getKey() {
    return key;
  }
  
  public String getPrecious() {
    return precious;
  }

}
