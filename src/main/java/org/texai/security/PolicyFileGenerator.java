/*
 * PolicyFileGenerator.java
 *
 * Created on Jan 25, 2010, 12:35:57 PM
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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 *
 * @author reed
 */
public final class PolicyFileGenerator {

  /** the permission rules buffered reader */
  private BufferedReader bufferedReader;
  /** policy file buffered writer */
  private BufferedWriter bufferedWriter;
  /** the code base dictionary, code base --> grant rule set */
  private Map<String, Set<String>> codeBaseDictionary = new HashMap<String, Set<String>>();

  /** Constructs a new PolicyFileGenerator instance. */
  public PolicyFileGenerator() {
  }

  /** Initializes this application. */
  private void initialization() {
    try {
      bufferedReader = new BufferedReader(new FileReader("policy-rules.txt"));
      bufferedWriter = new BufferedWriter(new FileWriter("texai.policy"));
    } catch (FileNotFoundException ex) {
      ex.printStackTrace();
    } catch (IOException ex) {
      ex.printStackTrace();
    }
  }

  /** Processes this application. */
  private void process() {
    while (true) {
      try {
        final String line = bufferedReader.readLine();
        if (line == null) {
          break;
        }
        System.out.println("line: " + line);
        if (line.startsWith("grant codeBase \"")) {
          final int index = line.indexOf('"', 17);
          final String codeBase = line.substring(16, index);
          System.out.println("  codeBase: " + codeBase);
          final String permission = line.substring(index + 3, line.length() - 2);
          System.out.println("  permission: " + permission);
          final String wildCardPermission = processWildCards(permission);
          if (!wildCardPermission.equals(permission)) {
            System.out.println("  wild card:  " + wildCardPermission);
          }
          Set<String> permissions = codeBaseDictionary.get(codeBase);
          if (permissions == null) {
            permissions = new HashSet<String>();
            codeBaseDictionary.put(codeBase, permissions);
          }
          permissions.add(wildCardPermission);
        }
      } catch (IOException ex) {
        ex.printStackTrace();
      }
    }
    System.out.println();
    try {
      bufferedWriter.write("// Texai permissions");
      bufferedWriter.newLine();
      String outputLine;
      final List<String> sortedCodeBases = new ArrayList<String>(codeBaseDictionary.keySet());
      Collections.sort(sortedCodeBases);
      for (final String sortedCodeBase : sortedCodeBases) {
        outputLine = "grant codeBase \"" + sortedCodeBase + "\" {";
        System.out.println(outputLine);
        bufferedWriter.write(outputLine);
        bufferedWriter.newLine();
        final List<String> sortedPermissions = new ArrayList<String>(codeBaseDictionary.get(sortedCodeBase));
        Collections.sort(sortedPermissions);
        for (final String sortedPermission : sortedPermissions) {
          outputLine = "  " + sortedPermission;
          System.out.println(outputLine);
          bufferedWriter.write(outputLine);
          bufferedWriter.newLine();
        }
        outputLine = "};";
        System.out.println(outputLine);
        System.out.println();
        bufferedWriter.write(outputLine);
        bufferedWriter.newLine();
        bufferedWriter.newLine();
      }
    } catch (IOException ex) {
      ex.printStackTrace();
    }
  }

  /** Returns the given permission string after substituting wild card expressions for unique file names.
   * 
   * @param permission the given permission string
   * @return the given permission string after substituting wild card expressions for unique file names
   */
  final String processWildCards(final String permission) {
    String wildCardString = permission;
    if (permission.startsWith("permission  java.io.FilePermission \"/tmp")) {
      final int index = permission.indexOf('\"', 40);
      return wildCardString.substring(0, 41) + "-" + wildCardString.substring(index);
    }
    int index = permission.indexOf("/var/cache/executor-snippets/junitvmwatcher");
    if (index > -1) {
      final int index2 = permission.indexOf('\"', index + 43);
      return wildCardString.substring(0, index + 29) + "-" + wildCardString.substring(index2);
    }

    // permission  java.io.FilePermission "/home/reed/.m2/repository/joda-time/joda-time/1.6/joda-time-1.6.jar", "read";
    index = permission.indexOf("m2/repository");
    if (index > -1) {
      final int index2 = permission.indexOf('\"', index + 14);
      return wildCardString.substring(0, index + 14) + "-" + wildCardString.substring(index2);
    }

    // permission  java.io.FilePermission "./journals/AmericanEnglishConstructionAndLexicalCategoryRules-2010-01-25T14_06_16.728-06_00.jrnl", "delete";
    index = permission.indexOf("\"./journals/");
    if (index > -1) {
      final int index2 = permission.indexOf('\"', index + 12);
      return wildCardString.substring(0, index + 12) + "-" + wildCardString.substring(index2);
    }

    // permission  java.io.FilePermission "/home/reed/archiveRepositories/OpenCyc", "read";
    index = permission.indexOf("/archiveRepositories/");
    if (index > -1) {
      final int index2 = permission.indexOf('\"', index + 21);
      return wildCardString.substring(0, index + 21) + "-" + wildCardString.substring(index2);
    }

    //  permission  java.io.FilePermission "/home/reed/repositories/DialogWordStemUsage/txn-status", "read";
    index = permission.indexOf("/repositories/");
    if (index > -1) {
      final int index2 = permission.indexOf('\"', index + 14);
      return wildCardString.substring(0, index + 14) + "-" + wildCardString.substring(index2);
    }

    index = permission.indexOf("/var/cache/executor-snippets/junitvmwatcher");
    if (index > -1) {
      final int index2 = permission.indexOf('\"', index + 43);
      return wildCardString.substring(0, index + 29) + "-" + wildCardString.substring(index2);
    }

    return wildCardString;
  }


  /** Finalizes this application. */
  private void finalization() {
    try {
      bufferedReader.close();
      bufferedWriter.close();
    } catch (IOException ex) {
      ex.printStackTrace();
    }
  }

  /** Executes this application.
   *
   * @param args the command line arguments - unused
   */
  public static void main(final String[] args) {
    final PolicyFileGenerator policyFileGenerator = new PolicyFileGenerator();
    policyFileGenerator.initialization();
    policyFileGenerator.process();
    policyFileGenerator.finalization();
  }
}
