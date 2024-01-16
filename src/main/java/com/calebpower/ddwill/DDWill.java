package com.calebpower.ddwill;

import java.util.ArrayList;
import java.util.List;

import com.calebpower.ddwill.CLIParser.CLIParam;
import com.calebpower.ddwill.CLIParser.CLIParseException;
import com.calebpower.ddwill.Fragment.BadFragReqException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONArray;
import org.json.JSONObject;

public class DDWill {
  
  public static void main(String... args) {
    
    final CLIParser parser = new CLIParser(System.out);
    
    try {
      parser.parse(args);
    } catch(CLIParseException e) {
      System.err.printf("Error: %1$s\n", e.getMessage());
      parser.printHelp();
      System.exit(1);
    }
    
    switch(parser.getCommand()) {
    
    case ENCRYPT:

      // get the input file from the disk
      DiskResource diskResource = new DiskResource(parser.getArg(CLIParam.FILE).get(0)).read();
      if(diskResource.getBytes() == null) {
        System.err.println("Error: Could not read file.");
        System.exit(2);
      }
      
      var requiredKeyCustodians = parser.getArg(CLIParam.REQUIRED_KEYS);
      var floatingKeyCustodians = parser.getArg(CLIParam.FLOATING_KEYS);
      var minFloaters = Integer.parseInt(parser.getArg(CLIParam.MINIMUM_FLOATERS).get(0));
      
      Fragment fileData = new Fragment(diskResource.getBytes());
      fileData.applyHash(); // hash the file data
      Key mainKey = new Key("MAIN KEY");
      fileData.encrypt(mainKey);
      
      byte[] mainKeyBuf = new byte[mainKey.getSecretBytes().length + mainKey.getIV().length];
      System.arraycopy( // copy the secret part of the main key into the buffer
          mainKey.getSecretBytes(),
          0,
          mainKeyBuf,
          0,
          mainKey.getSecretBytes().length);
      System.arraycopy( // copy the IV into the back half of the buffer
          mainKey.getIV(),
          0,
          mainKeyBuf,
          mainKey.getSecretBytes().length,
          mainKey.getIV().length);

      Fragment mainKeyFrag = new Fragment(mainKeyBuf); // construct the main key as a fragment
      
      Key[] requiredKeyArr = new Key[requiredKeyCustodians.size()];
      for(int i = 0; i < requiredKeyArr.length; i++) {
        requiredKeyArr[i] = new Key(requiredKeyCustodians.get(i));
        mainKeyFrag.applyHash(); // apply hash to the main key fragment
        mainKeyFrag.encrypt(requiredKeyArr[i]); // encrypt with the next required key
      }

      Fragment[] fileDataFrags = null;
      Fragment[] mainKeyFrags = null;
      try { // split the main key buffer into parts, one for each floating key custodian
        fileDataFrags = Fragment.split(fileData.getBytes(), floatingKeyCustodians.size());
        mainKeyFrags = Fragment.split(mainKeyBuf, floatingKeyCustodians.size());
      } catch(BadFragReqException e) {
        System.err.printf("Error: %1$s\n", e.getMessage());
        System.exit(2);
      }

      // calculate all of the floating keys
      Key[] floatingKeyArr = new Key[floatingKeyCustodians.size()];
      for(int i = 0; i < floatingKeyArr.length; i++)
        floatingKeyArr[i] = new Key(floatingKeyCustodians.get(i));

      // get combinations of all floating key custodians, we'll need this later
      List<int[]> comboIdxs = getCombos(floatingKeyCustodians.size(), minFloaters - 1);

      // this is the part where we need to start assembling parcels for recpients;
      // so, we need to iterate through each of them put together their individual packages
      for(int i = 0; i < floatingKeyCustodians.size(); i++) {
        
        // assemble the fragments of the encrypted file that will be given to the custodian;
        // remember that these two arrays are the same size because it needs to be sized
        // one less than the number of floating custodians (so we can exclude the recipient)
        Fragment[] custodianFileFrags = new Fragment[fileDataFrags.length - 1];
        Fragment[] custodianKeyFrags = new Fragment[mainKeyFrags.length - 1];
        for(int j = 0; j < fileDataFrags.length; j++) { // iterate through the file frags
          if(i == j) continue; // skip the one associated with this recipient
          // make sure to account for the index that was skipped
          custodianFileFrags[j > i ? j - 1 : j] = fileDataFrags[j];
          custodianKeyFrags[j > i ? j - 1 : j] = mainKeyFrags[j];
        }

        // get all combinations of the other custodians (exclude this recipient)
        List<Key[]> comboList = new ArrayList<>();
        for(var comboIdxArr : comboIdxs) {
          if(!Arrays.contains(comboIdxArr, i)) { // exclude recipient
            // then, essentially map the custodian index to the recipient
            Key[] keyArr = new Key[comboIdxArr.length];
            for(int k = 0; k < comboIdxArr.length; k++)
              keyArr[k] = floatingKeyArr[comboIdxArr[k]];
            comboList.add(keyArr); // add to the list of combos
          }
        }

        // here, we're just copying the recipient's key fragment so we can
        // encrypt each copy with a different key combination; remember that
        // we're just encrypting the main key, not the file itself
        Fragment[] encKeyFrags = new Fragment[comboList.size()];
        Fragment mergedFileFrags = null;

        try {
          encKeyFrags[0] = new Fragment(Fragment.join(custodianKeyFrags));
          mergedFileFrags = new Fragment(Fragment.join(custodianFileFrags));
        } catch(BadFragReqException e) {
          System.err.printf("Error: %1$s\n", e.getMessage());
          System.exit(2);
        }

        // make a copy of each fragment and encrypt them
        for(int j = 0; j < encKeyFrags.length; j++) {
          if(0 < j)
            encKeyFrags[j] = new Fragment(encKeyFrags[0]); // deep copy is important

          // for each key
          var keyCombo = comboList.get(j);
          for(int k = 0; k < keyCombo.length; k++) {
            encKeyFrags[j].applyHash(); // apply a hash
            encKeyFrags[j].encrypt(keyCombo[k]); // encrypt the fragment
          }
        }

        // at this point, we're done encrypting things; time to format them
        JSONArray keyArr = new JSONArray();
        for(var keyFrag : encKeyFrags)
          keyArr.put(
              Base64.toBase64String(
                  keyFrag.getBytes()));
        JSONObject custodianData = new JSONObject()
          .put(
              "f",
              Base64.toBase64String(
                  mergedFileFrags.getBytes()))
          .put("k", keyArr);

        System.err.println(custodianData.toString(2));
      }

      break;
      
      
    case DECRYPT:
      break;
      
      
      
      
      
    
    }
    
  }
  
  private static List<int[]> getCombos(int max, int count) {
    int[] arr = new int[max];
    for(int i = 0; i < max; i++)
      arr[i] = i;
    
    List<int[]> subsets = new ArrayList<>();
    int[] idxs = new int[count];
    if(count < arr.length) {
      for(int i = 0; (idxs[i] = i) < count - 1; i++);
      subsets.add(getSubset(arr, idxs));
      for(;;) {
        int i;
        for(i = count - 1; i >= 0 && idxs[i] == arr.length - count + i; i--);
        if(i < 0) break;
        idxs[i]++;
        for(++i; i < count; i++) idxs[i] = idxs[i - 1] + 1;
        subsets.add(getSubset(arr, idxs));
      }
    }
    
    return subsets;
  }
  
  private static int[] getSubset(int[] input, int[] subset) {
    int[] result = new int[subset.length];
    for(int i = 0; i < subset.length; i++)
      result[i] = input[subset[i]];
    return result;
  }
  
}




















