package com.calebpower.ddwill;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.calebpower.ddwill.CLIParser.CLICommand;
import com.calebpower.ddwill.CLIParser.CLIParam;
import com.calebpower.ddwill.CLIParser.CLIParseException;

/**
 * Test class to test {@link CLIParser}.
 * 
 * @author Caleb L. Power
 */
public class CLIParserTest {
  
  private final CLIParser parser = new CLIParser(null);

  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it'll fail
   * gracefully when provided with an array of arguments that end with a
   * hanging parameter-- that is, a flag without an established argument.
   */
  @Test public void testParse_hangingParamAtEnd() {
    try {
      parser.parse("encrypt", "--file", "testFile", "-r");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Cannot have a hanging parameter.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it'll fail
   * gracefully when provided with an array of arguments that contain a
   * parameter flag that has no matching argument or arguments.
   */
  @Test public void testParse_hangingParamInMiddle() {
    try {
      parser.parse("encrypt", "--file", "-r", "key");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Cannot have a hanging parameter.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully when more than one base command is provided.
   */
  @Test public void testParse_tooManyCommands() {
    try {
      parser.parse("encrypt", "decrypt", "--file", "location", "-r", "key");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Cannot specify more than one command.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully when some string is passed in as the base command that in fact
   * does not match one of the two possible options (i.e. encrypt or decrypt).
   */
  @Test public void testParse_badCommand() {
    try {
      parser.parse("eat", "--file", "location", "-r", "key");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Bad command specified: \"eat\"");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully when no base command (i.e. encrypt, decrypt) is specified.
   */
  @Test public void testParse_missingCommand() {
    try {
      parser.parse("--file", "location", "-r", "key");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Must specify exactly one command.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if a filename is not specified for the encryption base command.
   */
  @Test public void testParse_missingFileForEncrypt() {
    try {
      parser.parse("encrypt", "-r", "key");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Must specify a file to read from.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if input keys are specified in conjunction with the 'encrypt'
   * base parameter, as this would be an invalid intention.
   */
  @Test public void testParse_badInputKeySpecForEncrypt() {
    try {
      parser.parse("encrypt", "--file", "nail", "-k", "blah", "blah2", "-r", "key");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Input keys may not be specified when encrypting.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if neither required nor floating keys are specified when the
   * 'encrypt' base command is specified.
   */
  @Test public void testParse_missingKeysForEncrypt() {
    try {
      parser.parse("encrypt", "--file", "nail");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Floating and/or required keys must be specified for encryption.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if no file is specified for decryption output.
   */
  @Test public void testParse_missingFileForDecrypt() {
    try {
      parser.parse("decrypt", "-k", "key");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Must specify a file to write to.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if the required key flag is specified at the same time that the
   * decryption base command is issued, as this would indicate an invalid
   * intention.
   */
  @Test public void testParse_badRequiredKeySpecForDecrypt() {
    try {
      parser.parse("decrypt", "--file", "nail", "-k", "key", "-r", "required");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Invalid parameter(s) specified for decryption.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if the floater key flag is specified at the same time that the
   * decryption base command is issued, as this would indicate an invalid
   * intention.
   */
  @Test public void testParse_badFloatingKeySpecForDecrypt() {
    try {
      parser.parse("decrypt", "--file", "nail", "-k", "key", "-l", "floater");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Invalid parameter(s) specified for decryption.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if the minimum floater key count flag is specified at the same
   * time that the decryption base command is issued, as this would indicate an
   * invalid intention.
   */
  @Test public void testParse_badMinimumFloaterSpecForDecrypt() {
    try {
      parser.parse("decrypt", "--file", "nail", "-k", "key", "-m", "20");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Invalid parameter(s) specified for decryption.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if no input keys are specified for decryption.
   */
  @Test public void testParse_missingInputKeyForDecrypt() {
    try {
      parser.parse("decrypt", "--file", "nail");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Input key(s) must be specified for decryption.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if one or more floating key custodians are specified, but the
   * minimum floating key count is missing.
   */
  @Test public void testParse_missingFloaterCount() {
    try {
      parser.parse("encrypt", "--file", "nail", "-r", "req", "another_req", "-l", "floater");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Minimum floater count must be specified when using floating keys.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if the minimum floating key count cannot be parsed as an
   * integer.
   */
  @Test public void testParse_badMinFloaterParse() {
    try {
      parser.parse("encrypt", "--file", "nail", "-r", "req", "another_req", "-l", "floater", "-m", "BLAH");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Minimum floater count must be a positive integer.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if the minimum floating key count represents some non-positive
   * integer value.
   */
  @Test public void testParse_badMinFloaterVal() {
    try {
      parser.parse("encrypt", "--file", "nail", "-r", "req", "another_req", "-l", "floater", "-m", "-3");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Minimum floater count must be a positive integer.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if more than one file argument is specified.
   */
  @Test public void testParse_tooManyFileArgs() {
    try {
      parser.parse("encrypt", "--file", "foo", "bar", "-r", "req", "another_req", "-l", "f1", "f2", "-m", "2");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Too many args passed for file param.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if more than one minimum floating key count is specified.
   */
  @Test public void testParse_tooManyMinFloaterCountArgs() {
    try {
      parser.parse("encrypt", "--file", "foo", "-r", "req", "another_req", "-l", "f1", "f2", "f3", "-m", "3", "2");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Too many args passed for minimum floater count.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it fails
   * gracefully if the specified minimum floating key count is larger than the
   * number of specified floating keys.
   */
  @Test public void testParse_oobFloaterCountVal() {
    try {
      parser.parse("encrypt", "--file", "foo", "-r", "req", "another_req", "-l", "floater", "-m", "4");
      Assert.fail("CLIParseException failed to be thrown.");
    } catch(CLIParseException e) {
      Assert.assertEquals(e.getMessage(), "Minimum floater count exceeds number of specified floating keys.");
    }
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it is able to
   * properly parse a valid encryption directive.
   * 
   * @throws CLIParseException iff the provided command line arguments could
   *         not be parsed or were otherwise invalid.
   */
  @Test public void testParse_successfulEncrypt() throws CLIParseException {
    parser.parse("encrypt", "--file", "foo", "-r", "bar", "baz", "-l", "alpha", "beta", "gamma", "-m", "2");
    Assert.assertEquals(parser.getCommand(), CLICommand.ENCRYPT);
    Assert.assertEquals(parser.getArg(CLIParam.FILE).size(), 1);
    Assert.assertEquals(parser.getArg(CLIParam.FILE).get(0), "foo");
    Assert.assertEquals(parser.getArg(CLIParam.REQUIRED_KEYS).size(), 2);
    Assert.assertEquals(parser.getArg(CLIParam.REQUIRED_KEYS).get(0), "bar");
    Assert.assertEquals(parser.getArg(CLIParam.REQUIRED_KEYS).get(1), "baz");
    Assert.assertEquals(parser.getArg(CLIParam.FLOATING_KEYS).size(), 3);
    Assert.assertEquals(parser.getArg(CLIParam.FLOATING_KEYS).get(0), "alpha");
    Assert.assertEquals(parser.getArg(CLIParam.FLOATING_KEYS).get(1), "beta");
    Assert.assertEquals(parser.getArg(CLIParam.FLOATING_KEYS).get(2), "gamma");
    Assert.assertEquals(parser.getArg(CLIParam.MINIMUM_FLOATERS).size(), 1);
    Assert.assertEquals(parser.getArg(CLIParam.MINIMUM_FLOATERS).get(0), "2");
    Assert.assertEquals(parser.getArg(CLIParam.INPUT_KEYS), null);
  }
  
  /**
   * Tests {@link CLIParser#parse(String...)} to ensure that it is able to
   * properly parse a valid decryption directive.
   * 
   * @throws CLIParseException iff the provided command line arguments could
   *         not be parsed or were otherwise invalid.
   */
  @Test public void testParse_successfulDecrypt() throws CLIParseException {
    parser.parse("decrypt", "--file", "foo", "-k", "tau", "kappa", "epsilon");
    Assert.assertEquals(parser.getCommand(), CLICommand.DECRYPT);
    Assert.assertEquals(parser.getArg(CLIParam.FILE).size(), 1);
    Assert.assertEquals(parser.getArg(CLIParam.FILE).get(0), "foo");
    Assert.assertEquals(parser.getArg(CLIParam.INPUT_KEYS).size(), 3);
    Assert.assertEquals(parser.getArg(CLIParam.INPUT_KEYS).get(0), "tau");
    Assert.assertEquals(parser.getArg(CLIParam.INPUT_KEYS).get(1), "kappa");
    Assert.assertEquals(parser.getArg(CLIParam.INPUT_KEYS).get(2), "epsilon");
    Assert.assertEquals(parser.getArg(CLIParam.REQUIRED_KEYS), null);
    Assert.assertEquals(parser.getArg(CLIParam.FLOATING_KEYS), null);
    Assert.assertEquals(parser.getArg(CLIParam.MINIMUM_FLOATERS), null);
  }
  
}
