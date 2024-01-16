package com.calebpower.ddwill;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Handles the parsing of command line arguments.
 * 
 * @author Caleb L. Power
 */
public class CLIParser {
  
  /**
   * The base operation that the program should execute.
   * 
   * @author Caleb L. Power
   */
  public static enum CLICommand {
    
    /**
     * Indicates that the software is going to encrypt and split up a file.
     */
    ENCRYPT,
    
    /**
     * Indicates that the software is going do join and decrypt a file.
     */
    DECRYPT
    
  }
  
  /**
   * Denotes some parameter passed along to the base operation.
   * 
   * @author Caleb L. Power
   */
  public static enum CLIParam {
    
    /**
     * The file that is either being read from or written to.
     */
    FILE("-f", "--file", "<file>", "the input or output file"),
    
    /**
     * The keys that will be required to unlock the file.
     */
    REQUIRED_KEYS("-r", "--required-keys", "<custodian> [custodian...]", "those who shall hold required keys"),
    
    /**
     * The keys that will be optionally used to unlock the file.
     */
    FLOATING_KEYS("-l", "--floating-keys", "<custodian> [custodian...]", "those who shall hold floating keys"),
    
    /**
     * The minimum number of floating keys required to unlock the file.
     */
    MINIMUM_FLOATERS("-m", "--minimum-floaters", "<1..n>", "the minimum number of required floating keys"),
    
    /**
     * The set of keys that are going to be used to reconstruct the file.
     */
    INPUT_KEYS("-k", "--input-keys", "<keyfile> [keyfile...]", "keyfiles needed for decryption");
    
    private String shortFlag = null;
    private String longFlag = null;
    private String paramList = null;
    private String description = null;
    
    private CLIParam(String shortFlag, String longFlag, String paramList, String description) {
      this.shortFlag = shortFlag;
      this.longFlag = longFlag;
      this.paramList = paramList;
      this.description = description;
    }
    
    /**
     * Retrieves the parameter that corresponds with the provided flag.
     * 
     * @param flag the command line flag or switch
     * @return the matching CLIParam enumerable object or {@code null} if no
     *         CLIParam instance exists
     */
    public static CLIParam fromFlag(String flag) {
      flag = flag.toLowerCase();
      for(var param : values())
        if(param.shortFlag.equalsIgnoreCase(flag)
            || param.longFlag.equalsIgnoreCase(flag))
          return param;
      return null;
    }
  }
  
  private PrintStream out = null;
  private CLICommand command = null;
  private Map<CLIParam, List<String>> args = new HashMap<>();
  
  /**
   * Instantiates the parser.
   * 
   * @param out the output stream, for printing help messages
   */
  public CLIParser(PrintStream out) {
    this.out = out;
  }
  
  /**
   * Parses an array of arguments.
   * 
   * @param args the arguments, presumably from the command line
   * @throws CLIParseException iff the sequence of arguments yields an invalid
   *         or nonsensical result
   */
  public void parse(String... args) throws CLIParseException {
    this.command = null;
    this.args.clear();
    
    CLIParam lastParam = null;
    for(int i = 0; i < args.length; i++) {
      var arg = args[i];
      CLIParam currentParam = CLIParam.fromFlag(arg);
      if(currentParam != null) {
        
        if(i == args.length - 1
            || lastParam != null
            && (!this.args.containsKey(lastParam)
                || this.args.get(lastParam) == null))
          throw new CLIParseException("Cannot have a hanging parameter.");
        
        lastParam = currentParam;
        continue;
      }
      
      if(lastParam == null) {
        if(this.command != null)
          throw new CLIParseException("Cannot specify more than one command.");
        try {
          var command = CLICommand.valueOf(arg.toUpperCase());
          this.command = command;
        } catch(IllegalArgumentException e) {
          throw new CLIParseException(String.format("Bad command specified: \"%1$s\"", arg));
        }
        continue;
      }
      
      this.args.putIfAbsent(lastParam, new ArrayList<>());
      this.args.get(lastParam).add(arg);
    }
    
    if(this.command == null)
      throw new CLIParseException("Must specify exactly one command.");
    
    switch(this.command) {
    case ENCRYPT:
      
      if(!this.args.containsKey(CLIParam.FILE))
        throw new CLIParseException("Must specify a file to read from.");
      
      if(this.args.containsKey(CLIParam.INPUT_KEYS))
        throw new CLIParseException("Input keys may not be specified when encrypting.");
      
      if(!this.args.containsKey(CLIParam.FLOATING_KEYS)
          && !this.args.containsKey(CLIParam.REQUIRED_KEYS))
        throw new CLIParseException("Floating and/or required keys must be specified for encryption.");
      
      break;
      
    case DECRYPT:
      
      if(!this.args.containsKey(CLIParam.FILE))
        throw new CLIParseException("Must specify a file to write to.");
      
      if(this.args.containsKey(CLIParam.REQUIRED_KEYS)
          || this.args.containsKey(CLIParam.FLOATING_KEYS)
          || this.args.containsKey(CLIParam.MINIMUM_FLOATERS))
        throw new CLIParseException("Invalid parameter(s) specified for decryption.");
      
      if(!this.args.containsKey(CLIParam.INPUT_KEYS))
        throw new CLIParseException("Input key(s) must be specified for decryption.");
      
      break;
    }

    for(var arg : this.args.entrySet())
      if(arg.getValue().isEmpty())
        throw new CLIParseException("Must specify arg for param %1$s", arg.getKey().toString());

    if(this.args.containsKey(CLIParam.FLOATING_KEYS)
        && !this.args.containsKey(CLIParam.MINIMUM_FLOATERS))
      throw new CLIParseException("Minimum floater count must be specified when using floating keys.");
    
    if(this.args.containsKey(CLIParam.MINIMUM_FLOATERS)) {
      int minFloaters = 0;
      try {
        minFloaters = Integer.parseInt(this.args.get(CLIParam.MINIMUM_FLOATERS).get(0));
      } catch(NullPointerException | NumberFormatException e) { }
      if(minFloaters <= 0) throw new CLIParseException("Minimum floater count must be a positive integer.");
      if(minFloaters > this.args.get(CLIParam.FLOATING_KEYS).size())
        throw new CLIParseException("Minimum floater count exceeds number of specified floating keys.");
    }
    
    if(this.args.containsKey(CLIParam.FILE)
        && this.args.get(CLIParam.FILE).size() > 1)
      throw new CLIParseException("Too many args passed for file param.");
    
    if(this.args.containsKey(CLIParam.MINIMUM_FLOATERS)
        && this.args.get(CLIParam.MINIMUM_FLOATERS).size() > 1)
      throw new CLIParseException("Too many args passed for minimum floater count.");

    Set<String> keyNames = new HashSet<>();
    for(var param : new CLIParam[] { CLIParam.FLOATING_KEYS, CLIParam.INPUT_KEYS, CLIParam.REQUIRED_KEYS })
      for(var key : this.args.get(param))
        if(!keyNames.add(key.replaceAll("\\s+", "_").toLowerCase()))
          throw new CLIParseException("Duplicate keys specified.");
  }
  
  /**
   * Retrieves the main command associated with the parsed arguments.
   * 
   * @return the CLICommand argument associated with the parsed arguments, or
   *         {@code null} if an array of arguments has yet to be successfully
   *         parsed
   */
  public CLICommand getCommand() {
    return command;
  }
  
  /**
   * Retrieves the argument(s) associated with the provided parameter.
   * 
   * @param param the CLIParam enumerable object associated with the desired
   *        argument
   * @return a list of String objects denoting the arguments associated with
   *         the provided parameter
   */
  public List<String> getArg(CLIParam param) {
    return args.get(param);
  }
  
  /**
   * Prints a helpful message to the known PrintStream object.
   */
  public void printHelp() {
    if(out == null) return;
    
    out.println("\nddWill - Copyright (c) 2021-2024 Caleb L. Power\n");
    out.println("Usage: java -jar ddWill.jar encrypt|decrypt <options...>\n");
    out.println("Options:");
    int topOptionLen = 0;
    List<StringBuilder> options = new ArrayList<>();
    for(var param : CLIParam.values()) {
      StringBuilder sb = new StringBuilder()
          .append("  ")
          .append(param.shortFlag)
          .append(", ")
          .append(param.longFlag)
          .append(' ')
          .append(param.paramList)
          .append(" : ");
      if(sb.length() > topOptionLen) {
        topOptionLen = sb.length();
        for(int i = 0; i < options.size(); i++) {
          int len = 0;
          while((len = sb.length()) < topOptionLen)
            sb.insert(len - 2, ' ');
        }
      }
      options.add(sb);
    }
    for(int i = 0; i < options.size(); i++)
      out.println(options.get(i).append(CLIParam.values()[i].description));
    out.println();
  }
  
  /**
   * An exception that is thrown if the provided arguments could not be
   * parsed confidently.
   * 
   * @author Caleb L. Power
   */
  public final class CLIParseException extends Exception {
    private static final long serialVersionUID = 1358400627176684994L;

    private CLIParseException(String message) {
      super(message);
    }
    
    private CLIParseException(String format, Object... args) {
      super(String.format(format, args));
    }
  }
  
}
