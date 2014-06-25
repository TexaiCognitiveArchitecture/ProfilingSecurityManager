/*

 * Copyright (c) 2006 Mark Petrovic <mspetrovic@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Original Author: Mark Petrovic <mspetrovic@gmail.com>
 *
 */
package org.texai.security;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URL;
import java.security.AccessController;
import java.security.AccessControlContext;
import java.security.CodeSource;
import java.security.Permission;
import java.security.ProtectionDomain;
import java.util.ArrayList;

/**
 * <code>ProfilingSecurityManager</code> is a Java security manager that profiles
 * what resources an application accesses, and in what manner --- e.g., read, write, etc.  It does not enforce a
 * security policy, but rather produces a starting point for crafting one.
 * <p>
 * It extends <code>java.lang.SecurityManager</code> and overrides the two forms of the <code>checkPermission()</code> method.
 * For each call to <code>checkPermission()</code>, <code>ProfilingSecurityManager</code> first guards against the
 * condition that it itself induced the call to <code>checkPermission()</code>, which would result in
 * unterminated recursion.  If a call to <code>checkPermission()</code> resulted from a call outside
 * <code>ProfilingSecurityManager</code>, the current context is examined and each class found therein is
 * profiled as needing access to the <code>java.security.Permission</code> in question.
 *
 * Profiling is manifested as a writing to <code>System.bufferedWriter</code> a "grant" rule for each <code>java.security.Permission</code> requested
 * on a per <code>CodeBase</code> basis.
 *
 * The implementation here does some very simple rule caching.  If a rule has been seen previously, it is not output to System.bufferedWriter.
 * The caching cannot prevent a security check, but it can reduce I/O during profiling.
 *
 * @author Mark S. Petrovic
 *
 * Revised by Stephen L. Reed, http://texai.org, January 25, 2010.
 */
public final class ProfilingSecurityManager extends SecurityManager {

  /* this class name */
  final private String thisClassName;
  /** this code source URL string */
  final private String thisCodeSourceURLString;
  /** the profiling security manager message */
  final private String psmMsg = "ProfilingSecurityManager";
  /** the rule output file */
  BufferedWriter bufferedWriter;
  /** the cached rules */
  final private ArrayList<String> cachedRules = new ArrayList<>();

  /** Constructs a new ProfilingSecurityManager instance. */
  public ProfilingSecurityManager() {
    thisClassName = this.getClass().getName();
    final CodeSource thisCodeSource = this.getClass().getProtectionDomain().getCodeSource();
    thisCodeSourceURLString = thisCodeSource.getLocation().toString();
    try {
      bufferedWriter = new BufferedWriter(new FileWriter("policy-rules.txt"));
    } catch (IOException ex) {
      ex.printStackTrace();
    }
  }

  /** Throws a <code>SecurityException</code> if the requested
   * access, specified by the given permission, is not permitted based
   * on the security policy currently in effect.
   * <p>
   * This method calls <code>AccessController.checkPermission</code>
   * with the given permission.
   *
   * @param permission the requested permission.
   */
  @Override
  public void checkPermission(final Permission permission) {
    //Preconditions
    assert permission != null : "permission must not be null";

    @SuppressWarnings({"ThrowableInstanceNotThrown"})
    final Throwable throwable = new Throwable("Profiler stack probe");
    final StackTraceElement[] stack = throwable.getStackTrace();
    // Avoid recursion owing to actions in this class itself inducing callbacks
    if (!isRecursive(stack)) {
      try {
        buildRules(permission, AccessController.getContext());
      } catch (IOException ex) {
        ex.printStackTrace();
      }
    }
  }

  /** Throws a <code>SecurityException</code> if the
   * specified security context is denied access to the resource
   * specified by the given permission.
   * The context must be a security
   * context returned by a previous call to
   * <code>getSecurityContext</code> and the access control
   * decision is based upon the configured security policy for
   * that security context.
   * <p>
   * If <code>context</code> is an instance of
   * <code>AccessControlContext</code> then the
   * <code>AccessControlContext.checkPermission</code> method is
   * invoked with the specified permission.
   * <p>
   * If <code>context</code> is not an instance of
   * <code>AccessControlContext</code> then a
   * <code>SecurityException</code> is thrown.
   *
   * @param permission the specified permission
   * @param context a system-dependent security context.
   * @exception  SecurityException  if the specified security context is not an instance of
   * <code>AccessControlContext</code> (e.g., is <code>null</code>), or is denied access to
   * the resource specified by the given permission.
   */
  @Override
  public void checkPermission(final Permission permission, final Object context) {
    //Preconditions
    assert permission != null : "permission must not be null";
    assert context != null : "context must not be null";

    try {
      buildRules(permission, (AccessControlContext) context);
    } catch (IOException ex) {
      ex.printStackTrace();
    }
  }

  // With a Permission and an AccessControlContext, we can build and print rules
  /** Builds and prints rules.
   *
   * @param permission the permission
   * @param accessControlContext the access control context
   * @throws java.io.IOException when an I/O error occurs
   */
  private void buildRules(final Permission permission, final AccessControlContext accessControlContext) throws IOException {
    //Preconditions
    assert permission != null : "permission must not be null";
    assert accessControlContext != null : "accessControlContext must not be null";

    try {
      final ProtectionDomain[] protectionDomain = getProtectionDomains(accessControlContext);
      if (null != protectionDomain) {
        for (int i = 0; i < protectionDomain.length; ++i) {
          final String formattedGrantRule = formatRule(permission, protectionDomain[i]);
          if (null != formattedGrantRule && !isCached(formattedGrantRule)) {
            System.out.println(formattedGrantRule);
            bufferedWriter.write(formattedGrantRule);
            bufferedWriter.write('\n');
            bufferedWriter.flush();
          }
        }
      }
    } catch (IllegalStateException ex) {
      ex.printStackTrace();
    }
  }

  /** Returns whether we recursively called ourself.
   *
   * @param stackTraceElementStack the stack trace element stack
   * @return whether we recursively called ourself
   */
  private boolean isRecursive(final StackTraceElement[] stackTraceElementStack) {
    //Preconditions
    assert stackTraceElementStack != null : "stackTraceElement must not be null";

    for (int i = stackTraceElementStack.length - 1; i >= 1; --i) {
      final boolean isClassNameMatched = stackTraceElementStack[i].getClassName().equals(thisClassName);
      final boolean isMethodNameMatched = stackTraceElementStack[i].getMethodName().equals("buildRules");
      if (isClassNameMatched && isMethodNameMatched) {
        return true;
      }
    }
    return false;
  }

  /* Gets the protection domains by Java reflection.  There is no public API for this info,
   * making this code Sun Java 1.6 JVM implementation dependent.
   *
   * @param accessControlContext the access control context
   * @throws IllegalStateException when the accessControlContext cannot be found
   */
  private ProtectionDomain[] getProtectionDomains(final AccessControlContext accessControlContext) throws IllegalStateException {
    //Preconditions
    assert accessControlContext != null : "accessControlContext must not be null";

    ProtectionDomain[] protectionDomain = null;
    try {
      final Field[] fields = AccessControlContext.class.getDeclaredFields();
      if (null == fields) {
        throw new IllegalStateException("No fields");
      }
      for (int i = 0; i < fields.length; ++i) {
        if (fields[i].getName().equals("context")) {  // Warning:  JVM-dependent
          fields[i].setAccessible(true);
          final Object projectionDomains = fields[i].get(accessControlContext);
          protectionDomain = (ProtectionDomain[]) projectionDomains;
          break;
        }
      }

      // No 'context' field found, throw exception.
      if (null == protectionDomain) {
        throw new IllegalStateException("No \"context\" Field found!");
      }

    } catch (IllegalAccessException ex) {
      ex.printStackTrace();
    }
    return protectionDomain;
  }

  /** Formats the rule.
   *
   * @param permission the given permission
   * @param protectionDomain the permission domain
   * @return the formatted rule
   */
  private String formatRule(final Permission permission, final ProtectionDomain protectionDomain) {
    //Preconditions
    assert permission != null : "permission must not be null";
    assert protectionDomain != null : "protectionDomain must not be null";

    final CodeSource codeSource = protectionDomain.getCodeSource();

    if (null == codeSource) {
      return null;
    }
    final URL url = codeSource.getLocation();
    if (null == url) {
      return null;
    }

    // remove ProfilingSecurityManager.class codebase from output rule consideration
    if (url.toString().equals(thisCodeSourceURLString)) {
      return null;
    }

    final StringBuilder stringBuilder = new StringBuilder();
    stringBuilder.append("grant codeBase \"");
    stringBuilder.append(url.toString());
    stringBuilder.append("\" {");
    stringBuilder.append("permission ");
    stringBuilder.append(" ");
    stringBuilder.append(permission.getClass().getName());
    stringBuilder.append(" ");
    stringBuilder.append("\"");

    // some complex permissions have quoted strings embedded or
    // literal carriage returns that must be escaped

    final String permissionName = permission.getName();
    final String escapedPermissionName = permissionName.replace("\"", "\\\"").replace("\r", "\\\r");

    stringBuilder.append(escapedPermissionName);
    stringBuilder.append("\", ");
    stringBuilder.append("\"");
    stringBuilder.append(permission.getActions());
    stringBuilder.append("\";");
    stringBuilder.append("};");
    return stringBuilder.toString();
  }

  /** Returns whether the given candidate rule is cached.
   *
   * @param candidateRule the given candidate rule
   * @return whether the given candidate rule is cached
   */
  private boolean isCached(final String candidateRule) {
    //Preconditions
    assert candidateRule != null : "candidateRule must not be null";
    assert !candidateRule.isEmpty() : "candidateRule must not be empty";

    synchronized (cachedRules) {
      for (String cachedRule : cachedRules) {
        if (cachedRule.equals(candidateRule)) {
          return true;
        }
      }
      cachedRules.add(candidateRule);
    }
    return false;
  }

  /** Returns a string represnentation of this object.
   *
   * @return a string represnentation of this object
   */
  @Override
  public String toString() {
    return "SecurityManager:  " + psmMsg;
  }

  /** Closes the output file.  Called by the garbage collector on an object when garbage collection determines
   * that there are no more references to the object.
   *
   * @throws java.lang.Throwable when an error occurs
   */
  @Override
  @SuppressWarnings("FinalizeDeclaration")
   public void finalize() throws Throwable {
    try {
      bufferedWriter.close();
    } catch (IOException ex) {
      ex.printStackTrace();
    } finally {
      super.finalize();
    }
  }
}
