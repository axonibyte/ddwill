/*
 * Copyright (c) 2020 Axonibyte Innovations, LLC. All rights reserved.
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *   
 *   https://apache.org/licenses/LICENSE-2.0
 *   
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the license.
 * 
 * This file was modified so that it would read and make available an array of
 * bytes as opposed to a String. Such modifications were made 2021-12-16 by
 * Caleb L. Power and are subject to the same license.
 */
package com.calebpower.ddwill;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;

/**
 * Represents a resource read from the disk.
 * 
 * @author Caleb L. Power
 */
public class DiskResource {
  
  private byte[] data = null;
  private String resource = null;
  
  /**
   * Instantiates a model of a resource on the disk.
   * 
   * @param resource the path to the resource
   */
  public DiskResource(String resource) {
    this.resource = resource;
  }
  
  /**
   * Reads a resource as a binary. The resource can be in the classpath, in the
   * JAR (if compiled as such), or on the disk. <em>Reads the entire file at
   * once--so it's probably not wise to read huge files at one time.</em>
   * 
   * @return this disk resource object 
   */
  public DiskResource read() {
    InputStream inputStream = null;
    
    if(resource != null) try {
      File file = new File(resource);
      
      if(file.canRead())
        inputStream = new FileInputStream(file);
      else
        inputStream = DiskResource.class.getResourceAsStream(resource);
      
      if(inputStream != null)
        data = IOUtils.toByteArray(inputStream);
    } catch(IOException e) {
      e.printStackTrace(System.err);
      this.data = null;
    } finally {
      if(inputStream != null) try {
        inputStream.close();
      } catch(IOException e) { }
    }
    
    return this;
  }
  
  /**
   * Retrieves bytes read from the resource.
   * 
   * @return an array of bytes or {@code null} if none were read.
   */
  public byte[] getBytes() {
    return data;
  }
  
}