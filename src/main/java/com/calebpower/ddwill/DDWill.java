package com.calebpower.ddwill;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import com.calebpower.ddwill.CLIParser.CLIParam;
import com.calebpower.ddwill.CLIParser.CLIParseException;
import com.calebpower.ddwill.Fragment.BadFragReqException;

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
      Key[] requiredKeyArr = new Key[requiredKeyCustodians.size()];
      for(int i = 0; i < requiredKeyArr.length; i++) {
        requiredKeyArr[i] = new Key(requiredKeyCustodians.get(i));
        fileData.encrypt(requiredKeyArr[i]);
      }

      /*
      Fragment[] fragments = null;
      
      try {
        // split the file; each floating recipient will have a missing piece of the file
        fragments = Fragment.split(diskResource.getBytes(), floatingKeyCustodians.size());
      } catch(BadFragReqException e) {
        System.err.printf("Error: %1$s\n", e.getMessage());
        System.exit(2);
      }
      
      Key[] floatingKeyArr = new Key[floatingKeyCustodians.size()];
      for(int i = 0; i < floatingKeyArr.length; i++)
        floatingKeyArr[i] = new Key(floatingKeyCustodians.get(i));
      
      var idxs = getCombos(floatingKeyCustodians.size(), minFloaters);
      */

      /*
      List<List<Fragment>> assignedFragments = new ArrayList<>();

      for(var idxArr : idxs) { // for every subset
        List<Fragment> fragmentsList = new ArrayList<>();
        
        Key[] kSubset = new Key[idxArr.length];
        for(int i = 0; i < idxArr.length; i++) // and for every custodian in that subset
          kSubset[i] = floatingKeyArr[idxArr[i]]; // get the custodian's key
        Key merged = Key.merge(kSubset); // and merge them
        for(int i = 0; i < idxArr.length; i++) { // for each custodian in the subset
          Fragment fragment = new Fragment(fragments[i]);
          fragment.encrypt(merged); // encrypt their fragment
          fragmentsList.add(fragment); // make sure to map that fragment to the custodian
        }
        
        assignedFragments.add(fragmentsList);
      }
      */

      /*
      Key merged = Key.merge(requiredKeyArr);
      for(int i = 0; i < assignedFragments.size(); i++) {
        System.out.printf("For custodian %1$s:\n", floatingKeyArr[i].getCustodian());
        for(var frag : assignedFragments.get(i)) {
          frag.encrypt(merged);
          System.out.printf("-> %1$s\n", Base64.getEncoder().encodeToString(frag.getBytes()));
        }
        System.out.println();
      }
      */
      
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




















