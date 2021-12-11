package com.calebpower.ddwill;

import java.util.Base64;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.calebpower.ddwill.Fragment.BadFragReqException;

/**
 * Test class to ensure that {@link Fragment} is working properly.
 * 
 * @author Caleb L. Power
 */
public final class FragmentTest {
  
  /**
   * Ensure that {@link Fragment#split(byte[], int)} fails gracefully when the
   * developer submits a null array to be split.
   */
  @Test public void testSplit_failOnNullArr() {
    try {
      Fragment.split(null, 1);
      Assert.fail("BadFragReqException was not thrown.");
    } catch(BadFragReqException e) {
      Assert.assertEquals(e.getMessage(), "Cannot split a null array");
    }
  }
  
  /**
   * Ensure that {@link Fragment#split(byte[], int)} fails gracefully when the
   * developer requests fewer than one fragment.
   */
  @Test public void testSplit_failOnBadPartSpec() {
    try {
      Fragment.split(new byte[]{}, 0);
      Assert.fail("BadFragReqException was not thrown.");
    } catch(BadFragReqException e) {
      Assert.assertEquals(e.getMessage(), "Cannot split into < 1 parts");
    }
  }
  
  /**
   * Ensure that {@link Fragment#split(byte[], int)} properly splits an array
   * of bytes into several fragments of appropriate size.
   * 
   * @throws BadFragReqException iff the bytes could not be split
   */
  @Test public void testSplit_success() throws BadFragReqException {
    final byte[] whole = new byte[] {
        0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef };
    final byte[][] parts = new byte[][] {
      { 0x01, (byte)0xab },
      { 0x23, (byte)0xcd },
      { 0x45, (byte)0xef },
      { 0x67 },
      { (byte)0x89 }
    };
    
    Fragment[] fragments = Fragment.split(whole, 5);
    Assert.assertEquals(fragments.length, 5);
    for(int i = 0; i < fragments.length; i++)
      Assert.assertEquals(fragments[i].getBytes(), parts[i]);
  }
  
  /**
   * Ensure that {@link Fragment#join(Fragment[])} fails gracefully when the
   * developer submits a null array to be joined.
   */
  @Test public void testJoin_failOnNullArr() {
    try {
      Fragment.join(null);
      Assert.fail("BadFragReqException was not thrown.");
    } catch(BadFragReqException e) {
      Assert.assertEquals(e.getMessage(), "Cannot join a null array");
    }
  }
  
  /**
   * Ensure that {@link Fragment#join(Fragment[])} fails gracefully when the
   * provided byte array lengths do not allow for appropriate merging.
   */
  @Test public void testJoin_failOnBadArrSizeDiff() {
    final Fragment[] fragments = new Fragment[] {
        new Fragment(new byte[] { 0x01, (byte)0xab, 0x2b, (byte)0xad }),
        new Fragment(new byte[] { 0x23, (byte)0xcd }),
        new Fragment(new byte[] { 0x45, (byte)0xef }),
        new Fragment(new byte[] { 0x67 }),
        new Fragment(new byte[] { (byte)0x89 })
    };

    try {
      Fragment.join(fragments);
      Assert.fail("BadFragReqException was not thrown.");
    } catch(BadFragReqException e) {
      Assert.assertEquals(e.getMessage(), "Cannot merge when maxArr.size > minArr.size + 1");
    }
  }
  
  /**
   * Ensure that {@link Fragment#join(Fragment[])} fails gracefully when the
   * provided byte array has elements whose lengths are not descending.
   */
  @Test public void testJoin_failOnBadArrSizeOrder() {
    final Fragment[] fragments = new Fragment[] {
        new Fragment(new byte[] { 0x23, (byte)0xcd }),
        new Fragment(new byte[] { 0x01, 0x2b, (byte)0xad }),
        new Fragment(new byte[] { 0x45, (byte)0xef }),
        new Fragment(new byte[] { 0x67 }),
        new Fragment(new byte[] { (byte)0x89 })
    };

    try {
      Fragment.join(fragments);
      Assert.fail("BadFragReqException was not thrown.");
    } catch(BadFragReqException e) {
      Assert.assertEquals(e.getMessage(), "Cannot merge when arr[i] < arr[i - 1]");
    }
  }
  
  /**
   * Ensure that {@link Fragment#join(Fragment[])} properly joins an array of
   * byte arrays into a single byte array.
   * 
   * @throws BadFragReqException iff the byte arrays could not be joined
   */
  @Test public void testJoin_success() throws BadFragReqException {
    final byte[] whole = new byte[] {
        0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef };
    final Fragment[] fragments = new Fragment[] {
        new Fragment(new byte[] { 0x01, (byte)0xab }),
        new Fragment(new byte[] { 0x23, (byte)0xcd }),
        new Fragment(new byte[] { 0x45, (byte)0xef }),
        new Fragment(new byte[] { 0x67 }),
        new Fragment(new byte[] { (byte)0x89 })
    };
    
    Assert.assertEquals(Fragment.join(fragments), whole);
  }
  
  /**
   * Ensure that {@link Fragment#encrypt(Key, byte[])} properly encrypts
   * plaintext when given a good key and initialization vector.
   */
  @Test public void testEncrypt() {
    final Key key = new Key("Alice", "cfVSPNqcgU/O5BamqxHalbXcTfMh14XEyU7y5rpdqs4=");
    final byte[] iv = Base64.getDecoder().decode("qVDYwQNbiWk1xoGJ");
    final byte[] plaintext = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    final byte[] ciphertext = {
        (byte)0xbd, (byte)0x93, (byte)0x9f,       0x4c,
              0x32,       0x7f,       0x0e, (byte)0xb7,
        (byte)0xf4, (byte)0xbd,       0x5b, (byte)0xbd,
              0x7b, (byte)0xd3,       0x67,       0x07,
        (byte)0x83,       0x50,       0x04, (byte)0xd1,
        (byte)0x94,       0x48, (byte)0xea, (byte)0x94
    };
    Fragment fragment = new Fragment(plaintext);
    fragment.encrypt(key, iv);
    Assert.assertEquals(fragment.getBytes(), ciphertext);
  }
  
  /**
   * Ensure that {@link Fragment#decrypt(Key, byte[])} properly decrypts
   * ciphertext when given a good key and initialization vector.
   */
  @Test public void testDecrypt() {
    final Key key = new Key("Alice", "cfVSPNqcgU/O5BamqxHalbXcTfMh14XEyU7y5rpdqs4=");
    final byte[] iv = Base64.getDecoder().decode("qVDYwQNbiWk1xoGJ");
    final byte[] plaintext = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    final byte[] ciphertext = {
        (byte)0xbd, (byte)0x93, (byte)0x9f,       0x4c,
              0x32,       0x7f,       0x0e, (byte)0xb7,
        (byte)0xf4, (byte)0xbd,       0x5b, (byte)0xbd,
              0x7b, (byte)0xd3,       0x67,       0x07,
        (byte)0x83,       0x50,       0x04, (byte)0xd1,
        (byte)0x94,       0x48, (byte)0xea, (byte)0x94
    };
    Fragment fragment = new Fragment(ciphertext);
    fragment.decrypt(key, iv);
    Assert.assertEquals(fragment.getBytes(), plaintext);
  }

}
