/*
 * ProfilingSecurityManagerTest.java
 *
 * Created on Jun 30, 2008, 12:20:31 PM
 *
 * Description: .
 *
 * Copyright (C) Jan 25, 2010 reed.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program;
 * if not, write to the Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
package org.texai.security;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

/**
 *
 * @author reed
 */
public class ProfilingSecurityManagerTest {

  public ProfilingSecurityManagerTest() {
  }

  @BeforeClass
  public static void setUpClass() throws Exception {
  }

  @AfterClass
  public static void tearDownClass() throws Exception {
  }

  @Before
  public void setUp() {
  }

  @After
  public void tearDown() {
  }

  /**
   * Test class ProfilingSecurityManager.
   */
  @org.junit.Test
  public void testProfilingSecurityManager() {
    System.out.println("ProfilingSecurityManager");
    assertNull(System.getSecurityManager());
    System.setSecurityManager(new ProfilingSecurityManager());
    assertNotNull(System.getSecurityManager());
  }
}
