package com.calebpower.ddwill;

public class DDWill {
  
  public static void main(String... args) throws CommandLineException {
    
    
  }
  
  public static class CommandLineException extends Exception {
    
    CommandLineException(String message) {
      super(message);
    }
    
  }
  
}
