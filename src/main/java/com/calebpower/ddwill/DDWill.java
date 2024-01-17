package com.calebpower.ddwill;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.calebpower.ddwill.CLIParser.CLIParam;
import com.calebpower.ddwill.CLIParser.CLIParseException;
import com.calebpower.ddwill.Fragment.BadFragReqException;

import org.bouncycastle.util.Arrays;

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
      
      {
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
      
        byte[] mainKeyBuf = mainKey.getAggregated();
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

          // at this point, we're done encrypting things; time to format them;
          // aggregate the encrypted key payloads for the other custodians
          byte[][] keyArr = new byte[encKeyFrags.length][];
          for(int j = 0; j < encKeyFrags.length; j++)
            keyArr[j] = encKeyFrags[j].getBytes();

          // wrap it all up an an object; this will constitute the parcel for this custodian
          FloatingParcel parcel = new FloatingParcel(
              floatingKeyCustodians.get(i),
              floatingKeyArr[i].getAggregated(),
              mergedFileFrags.getBytes(),
              keyArr);

          try(
              FileOutputStream fos = new FileOutputStream(
                  floatingKeyCustodians.get(i).replaceAll("\\s+", "_") + ".key");
              ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(parcel);
          } catch(IOException e) {
            System.err.printf("Error: %1$s\n", e.getMessage());
          }
        }

        // we also need to drop the required keys
        for(int i = 0; i < requiredKeyArr.length; i++) {
          Parcel parcel = new Parcel(
              requiredKeyCustodians.get(i),
              requiredKeyArr[i].getAggregated());

          try(
              FileOutputStream fos = new FileOutputStream(
                  requiredKeyCustodians.get(i).replaceAll("\\s+", "_") + ".key");
              ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(parcel);
          } catch(IOException e) {
            System.err.printf("Error: %1$s\n", e.getMessage());
          }
        }

        break;
      }
      
    case DECRYPT:
      {
        // we're going to read the input files and get parcels/keys from them on the fly
        // start by getting the input keys (the users themselves can't be expected to
        // know if they're required or floating custodians, so we need to determine that
        // for ourselves
        var inputKeyCustodians = parser.getArg(CLIParam.INPUT_KEYS);
        List<Parcel> requiredParcels = new ArrayList<>();
        List<FloatingParcel> floatingParcels = new ArrayList<>();
        for(var inputKeyCustodian : inputKeyCustodians) {
          try(
              FileInputStream fis = new FileInputStream(inputKeyCustodian);
              ObjectInputStream ois = new ObjectInputStream(fis)) {
            Object obj = ois.readObject();
            if(obj instanceof FloatingParcel) {
              floatingParcels.add((FloatingParcel)obj);
            } else if(obj instanceof Parcel) {
              requiredParcels.add((Parcel)obj);
            } else {
              System.err.println("Error: deserialized an object that was not a Parcel.");
              System.exit(2);
            }
          } catch(ClassNotFoundException | IOException e) {
            System.err.printf("Error: %1$s\n", e.getMessage());
            System.exit(2);
          }
        }

        if(1 > floatingParcels.size()) {
          System.err.println("Error: at least one floating parcel is required for reconstruction.");
          System.exit(2);
        }

        // okay, now we've got the persistent files loaded, let's reconstruct the
        // required keys
        Key[] requiredKeys = new Key[requiredParcels.size()];
        for(int i = 0; i < requiredParcels.size(); i++) {
          var parcel = requiredParcels.get(i);
          requiredKeys[i] = new Key(
              parcel.getCustodian(),
              parcel.getKey());
        }
      
        // let's go ahead and do the same for the floating keys, but also remember
        // that floating custodians also have a piece of the file and fragments of
        // the encrypted main key
        Key[] floatingKeys = new Key[floatingParcels.size()];
        Fragment[] ciphertextFrag = new Fragment[floatingParcels.size()];
        List<List<Fragment>> mainKeyFrags = new ArrayList<>();
        for(int i = 0; i < floatingParcels.size(); i++) {
          var parcel = floatingParcels.get(i);
          floatingKeys[i] = new Key(
              parcel.getCustodian(),
              parcel.getKey());
          ciphertextFrag[i] = new Fragment(parcel.getCiphertext());
          var parcelFragments = parcel.getFragments();
          List<Fragment> mkFragArr = new ArrayList<>();
          for(int j = 0; j < parcelFragments.length; j++)
            mkFragArr.add(new Fragment(parcelFragments[j]));
          mainKeyFrags.add(mkFragArr);
        }

        // keep track of successful keys
        List<List<List<Integer>>> successes = new ArrayList<>();
        int topSuccess = 0;

        // now, we need to go ahead try to decrypt the fragments provided by each custodian;
        // so, for every custodian:
        for(int i = 0; i < mainKeyFrags.size(); i++) {

          successes.add(new ArrayList<>());
          var mkFragLst = mainKeyFrags.get(i); // list of frags a custodian holds

          // each custodian has a bunch of fragments, so try to decrypt them all;
          // do it in reverse so we don't run into any concurrency issues;
          // so, for every fragment that a custodian has:
          for(int j = mkFragLst.size() - 1; j >= 0; j--) {

            successes.get(i).add(new ArrayList<>());

            // no point trying to decrypt fragments with the custodian's own key
            // because they're definitely encrypted with the other keys
            if(i == j) continue;

            // and we're going to try to decrypt it with each key; this loop
            // should terminate when (a) all floating keys have been used or
            // (b) when remaining floating keys don't yield successful results
            for(int k = 0; k < floatingKeys.length; k++) {
              
              // but again, we're skipping the current key because it's never
              // going to decrypt its own payload; also, we're going to make
              // sure we're not trying to decrypt with a key that was already
              // successful
              if(k == i || successes.get(i).get(j).contains(k)) continue;
              
              // copy it so that bad decryption doesn't break it
              Fragment mkFrag = new Fragment(mkFragLst.get(k).getBytes());
              mkFrag.decrypt(floatingKeys[k]);
              
              // if we've got a successful one, that's great!
              // strip the hash, reset this inner loop
              if(mkFrag.verifyHash()) {
                mkFrag.stripHash(); // strip the hash
                successes.get(i).get(j).add(k); // note this key as being successful
                mkFragLst.set(k, mkFrag); // replace the one in the original list
                k = -1; // restart the inner loop
              }
              
            }

            // keep track of our success -- we want the longest chain of
            // successes because those are going to be the most-decrypted
            // fragments we've got
            int successCount = successes.get(i).get(j).size();
            if(topSuccess < successCount) topSuccess = successCount;

          }
        }

        // at this point, we've got a bunch of main key fragments (each custodian
        // has a set); some of them are fully decrypted up to the point where
        // required keys are now, well, required; some of them aren't fully
        // decrypted; we can tell which ones are the "most" decrypted because
        // they line up with the ones that took the most keys to decrypt (as
        // they were only encrypted with the minimum number of floating keys in
        // the first place); so, let's toss out any fragments that we know are
        // not "the most decrypted" as it were (and, if the user only specified
        // the minimum number of keys, this should only be one per custodian,
        // though we might find more if the user specified more than the minimum
        // number of floating keys; we can probably use this to figure out the
        // original minimum key count)
        for(int i = successes.size() - 1; i >= 0; i--)
          for(int j = successes.get(i).size() - 1; j >= 0; j--)
            if(topSuccess > successes.get(i).get(j).size()) {
              successes.get(i).remove(j);
              mainKeyFrags.get(i).remove(j);
            }

        // now, we're left with only those main key fragments and successes that
        // are, presumably, only encrypted with the required keys; so, decrypt
        // them; since the required keys are always used (by definition), if we
        // get failures at this point then we know that we had a bad key somewhere
        for(int i = mainKeyFrags.size(); i >= 0; i --) {
          for(int j = mainKeyFrags.get(i).size(); j >= 0; j--) {
            Set<Key> usedReqKey = new HashSet<>();
            for(int k = 0; k < requiredKeys.length; k++) {

              // we don't want to repeat decryption with a key we've already used
              if(usedReqKey.contains(requiredKeys[k])) continue;

              // copy it so that ba decryption doesn't break it
              Fragment mkFrag = new Fragment(mainKeyFrags.get(i).get(j).getBytes());
              mkFrag.decrypt(requiredKeys[k]);

              // if we've got a successful one, that's great!
              // strip the hash, reset this inner loop
              if(mkFrag.verifyHash()) {
                mkFrag.stripHash(); // strip the hash
                usedReqKey.add(requiredKeys[k]);
                k = -1;
              }
            }

            // the fragment should be completely decrypted now, which means that
            // we should have used all required keys; if we didn't, remove the
            // fragment from circulation
            if(usedReqKey.size() != requiredKeys.length)
              mainKeyFrags.get(i).remove(j);
          }
        }

        // all main key fragments at this point should be decrypted, but they're
        // still missing a piece; we need to split them up and reconstruct them

        


        

        break;
      }
    
    }

    System.out.println("Done.");
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




















