ProfilingSecurityManager
========================

ProfilingSecurityManager is a Java security manager that profiles what resources an application accesses, and in what manner --- e.g., read, write, etc.  It does not enforce a security policy, but rather produces a starting point for crafting one.

It extends <code>java.lang.SecurityManager</code> and overrides the two forms of the <code>checkPermission()</code> method.  For each call to <code>checkPermission()</code>, <code>ProfilingSecurityManager</code> first guards against the condition that it itself induced the call to <code>checkPermission()</code>, which would result in unterminated recursion.  If a call to <code>checkPermission()</code> resulted from a call outside  <code>ProfilingSecurityManager</code>, the current context is examined and each class found therein is profiled as needing access to the <code>java.security.Permission</code> in question.

Profiling is manifested as a writing to <code>System.bufferedWriter</code> a "grant" rule for each <code>java.security.Permission</code> requested  on a per <code>CodeBase</code> basis.

The implementation here does some very simple rule caching.  If a rule has been seen previously, it is not output to System.bufferedWriter. The caching cannot prevent a security check, but it can reduce I/O during profiling.  

Authored by Mark S. Petrovic, and revised by Stephen L. Reed.
