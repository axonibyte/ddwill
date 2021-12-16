package com.calebpower.ddwill;

/**
 * A runtime exception to be thrown if the data could not be encrypted or
 * decrypted. If this is thrown, it probably means that the developer did
 * something dumb or the software is incompatible with the operating system
 * (the latter of which probably also implies that the developer did
 * something dumb).
 * 
 * @author Caleb L. Power
 */
public class CryptOpRuntimeException extends RuntimeException {
  private static final long serialVersionUID = -9193255122444430908L;

  /**
   * Instantiates the CryptOpRuntimeException with its cause.
   * 
   * @param cause the cause of this runtime exception
   */
  public CryptOpRuntimeException(Throwable cause) {
    super(cause);
  }
  
}
