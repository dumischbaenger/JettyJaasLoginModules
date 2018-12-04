package de.dumischbaenger.jetty;

//
// this work is based on https://github.com/eclipse/jetty.project/blob/jetty-9.4.x/jetty-jaas/src/main/java/org/eclipse/jetty/jaas/spi/LdapLoginModule.java
//
//========================================================================
//Copyright (c) 1995-2018 Mort Bay Consulting Pty. Ltd.
//------------------------------------------------------------------------
//All rights reserved. This program and the accompanying materials
//are made available under the terms of the Eclipse Public License v1.0
//and Apache License v2.0 which accompanies this distribution.
//
//  The Eclipse Public License is available at
//  http://www.eclipse.org/legal/epl-v10.html
//
//  The Apache License v2.0 is available at
//  http://www.opensource.org/licenses/apache2.0.php
//
//You may elect to redistribute this code under either of these licenses.
//========================================================================
//

import java.io.IOException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.eclipse.jetty.jaas.callback.ObjectCallback;
import org.eclipse.jetty.jaas.callback.ServletRequestCallback;
import org.eclipse.jetty.jaas.spi.AbstractLoginModule;
import org.eclipse.jetty.jaas.spi.AbstractLoginModule.JAASUserInfo;
import org.eclipse.jetty.jaas.spi.LdapLoginModule;
import org.eclipse.jetty.jaas.spi.UserInfo;
import org.eclipse.jetty.util.B64Code;
import org.eclipse.jetty.util.TypeUtil;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;
import org.eclipse.jetty.util.security.Credential;

/**
 * A LdapLoginModule for use with JAAS setups
 * <p>
 * The jvm should be started with the following parameter:
 * 
 * <pre>
* -Djava.security.auth.login.config=etc/ldap-loginModule.conf
 * </pre>
 * 
 * and an example of the ldap-loginModule.conf would be:
 * 
 * <pre>
* ldaploginmodule {
*    de.dumischbaenger.jetty.JettyLdapLogin required
*    debug="true"
*    useLdaps="false"
*    contextFactory="com.sun.jndi.ldap.LdapCtxFactory"
*    hostname="ldap.example.com"
*    port="389"
*    bindDn="cn=Directory Manager"
*    bindPassword="directory"
*    authenticationMethod="simple"
*    forceBindingLogin="false"
*    userBaseDn="ou=people,dc=alcatel"
*    userRdnAttribute="uid"
*    userIdAttribute="uid"
*    userPasswordAttribute="userPassword"
*    userObjectClass="inetOrgPerson"
*    roleBaseDn="ou=groups,dc=example,dc=com"
*    roleNameAttribute="cn"
*    roleMemberAttribute="uniqueMember"
*    roleObjectClass="groupOfUniqueNames";
*    };
 * </pre>
 */
public class JettyLdapLogin extends AbstractLoginModule {
  private static final Logger LOG = Log.getLogger(JettyLdapLogin.class);

  /**
   * hostname of the ldap server
   */
  private String _hostname;

  /**
   * port of the ldap server
   */
  private int _port;

  /**
   * Context.SECURITY_AUTHENTICATION
   */
  private String _authenticationMethod;

  /**
   * Context.INITIAL_CONTEXT_FACTORY
   */
  private String _contextFactory;

  /**
   * root DN used to connect to
   */
  private String _bindDn;

  /**
   * password used to connect to the root ldap context
   */
  private String _bindPassword;

  /**
   * object class of a user
   */
  private String _userObjectClass = "inetOrgPerson";

  /**
   * attribute that the principal is located
   */
  private String _userRdnAttribute = "uid";

  /**
   * attribute that the principal is located
   */
  private String _userIdAttribute = "cn";

  /**
   * name of the attribute that a users password is stored under
   * <p>
   * NOTE: not always accessible, see force binding login
   */
  private String _userPasswordAttribute = "userPassword";

  /**
   * base DN where users are to be searched from
   */
  private String _userBaseDn;

  /**
   * base DN where role membership is to be searched from
   */
  private String _roleBaseDn;

  /**
   * object class of roles
   */
  private String _roleObjectClass = "groupOfUniqueNames";

  /**
   * name of the attribute that a username would be under a role class
   */
  private String _roleMemberAttribute = "uniqueMember";

  /**
   * the name of the attribute that a role would be stored under
   */
  private String _roleNameAttribute = "roleName";

  private boolean _debug;

  /**
   * if the getUserInfo can pull a password off of the user then password
   * comparison is an option for authn, to force binding login checks, set this to
   * true
   */
  private boolean _forceBindingLogin = false;

  /**
   * When true changes the protocol to ldaps
   */
  private boolean _useLdaps = false;

  private DirContext _rootContext;

  public class LDAPUserInfo extends UserInfo {
    Attributes attributes;

    /**
     * @param userName
     *          the user name
     * @param credential
     *          the credential
     * @param attributes
     *          the user {@link Attributes}
     */
    public LDAPUserInfo(String userName, Credential credential, Attributes attributes) {
      super(userName, credential);
      this.attributes = attributes;
    }

    @Override
    public List<String> doFetchRoles() throws Exception {
      return getUserRoles(_rootContext, getUserName(), attributes);
    }

  }

  /**
   * get the available information about the user
   * <p>
   * for this LoginModule, the credential can be null which will result in a
   * binding ldap authentication scenario
   * <p>
   * roles are also an optional concept if required
   *
   * @param username
   *          the user name
   * @return the userinfo for the username
   * @throws Exception
   *           if unable to get the user info
   */
  @Override
  public UserInfo getUserInfo(String username) throws Exception {
    Attributes attributes = getUserAttributes(username);
    String pwdCredential = getUserCredentials(attributes);

    if (pwdCredential == null) {
      return null;
    }

    pwdCredential = convertCredentialLdapToJetty(pwdCredential);
    Credential credential = Credential.getCredential(pwdCredential);
    return new LDAPUserInfo(username, credential, attributes);
  }

  protected String doRFC2254Encoding(String inputString) {
    StringBuffer buf = new StringBuffer(inputString.length());
    for (int i = 0; i < inputString.length(); i++) {
      char c = inputString.charAt(i);
      switch (c) {
      case '\\':
        buf.append("\\5c");
        break;
      case '*':
        buf.append("\\2a");
        break;
      case '(':
        buf.append("\\28");
        break;
      case ')':
        buf.append("\\29");
        break;
      case '\0':
        buf.append("\\00");
        break;
      default:
        buf.append(c);
        break;
      }
    }
    return buf.toString();
  }

  /**
   * attempts to get the users LDAP attributes from the users context
   * <p>
   * NOTE: this is not an user authenticated operation
   *
   * @param username
   * @return the {@link Attributes} from the user
   * @throws LoginException
   */
  private Attributes getUserAttributes(String username) throws LoginException {
    SearchResult result = findUser(username);
    Attributes attributes = result.getAttributes();
    return attributes;
  }

  private String getUserCredentials(Attributes attributes) throws LoginException {
    String ldapCredential = null;

    Attribute attribute = attributes.get(_userPasswordAttribute);
    if (attribute != null) {
      try {
        byte[] value = (byte[]) attribute.get();

        ldapCredential = new String(value);
      } catch (NamingException e) {
        LOG.debug("no password available under attribute: " + _userPasswordAttribute);
      }
    }

    if (LOG.isDebugEnabled())
      LOG.debug("user cred is: " + ldapCredential);

    return ldapCredential;
  }

  /**
   * attempts to get the users roles from the root context
   * <p>
   * NOTE: this is not an user authenticated operation
   *
   * @param dirContext
   * @param username
   * @return
   * @throws LoginException
   */
  private List<String> getUserRoles(DirContext dirContext, String username, Attributes attributes)
      throws LoginException, NamingException {
    String rdnValue = username;
    Attribute attribute = attributes.get(_userRdnAttribute);
    if (attribute != null) {
      try {
        rdnValue = (String) attribute.get(); // switch to the value stored in the _userRdnAttribute if we can
      } catch (NamingException e) {
      }
    }

    String filter = "({0}={1})";

    Object[] filterArguments = new Object[] { _userRdnAttribute, rdnValue };

    SearchResult searchResult = findUser(dirContext, filter, filterArguments);

    return getUserRolesByDn(dirContext, searchResult.getNameInNamespace());
  }

  private List<String> getUserRolesByDn(DirContext dirContext, String userDn) throws NamingException {
    List<String> roleList = new ArrayList<>();

    if (dirContext == null || _roleBaseDn == null || _roleMemberAttribute == null || _roleObjectClass == null) {
      return roleList;
    }

    SearchControls ctls = new SearchControls();
    ctls.setDerefLinkFlag(true);
    ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    ctls.setReturningAttributes(new String[] { _roleNameAttribute });

    String filter = "(&(objectClass={0})({1}={2}))";
    Object[] filterArguments = { _roleObjectClass, _roleMemberAttribute, userDn };
    NamingEnumeration<SearchResult> results = dirContext.search(_roleBaseDn, filter, filterArguments, ctls);

    if (LOG.isDebugEnabled())
      LOG.debug("Found user roles?: " + results.hasMoreElements());

    while (results.hasMoreElements()) {
      SearchResult result = results.nextElement();

      Attributes attributes = result.getAttributes();

      if (attributes == null) {
        continue;
      }

      Attribute roleAttribute = attributes.get(_roleNameAttribute);

      if (roleAttribute == null) {
        continue;
      }

      NamingEnumeration<?> roles = roleAttribute.getAll();
      while (roles.hasMore()) {
        roleList.add(roles.next().toString());
      }
    }

    return roleList;
  }

  /**
   * since ldap uses a context bind for valid authentication checking, we override
   * login()
   * <p>
   * if credentials are not available from the users context or if we are forcing
   * the binding check then we try a binding authentication check, otherwise if we
   * have the users encoded password then we can try authentication via that
   * mechanic
   *
   * @return true if authenticated, false otherwise
   * @throws LoginException
   *           if unable to login
   */
  @Override
  public boolean login() throws LoginException {
    try {
      if (getCallbackHandler() == null) {
        throw new LoginException("No callback handler");
      }

//      Callback[] callbacks = configureCallbacks();
      Callback[] callbacks = new Callback[4];
      callbacks[0] = new NameCallback("Enter user name");
      callbacks[1] = new ObjectCallback();
      callbacks[2] = new PasswordCallback("Enter password", false); //only used if framework does not support the ObjectCallback
      callbacks[3] = new ServletRequestCallback();
      
      getCallbackHandler().handle(callbacks);

      String webUserName = ((NameCallback) callbacks[0]).getName();
      Object webCredential = ((ObjectCallback) callbacks[1]).getObject();
      ServletRequest servletRequest=((ServletRequestCallback)callbacks[3]).getRequest();
      

      if (_debug) {
        String pwShort = "unknown";
        if (webCredential instanceof String) {
          String pw = (String) webCredential;
          pwShort = pw.charAt(0) + "..." + pw.charAt(pw.length() - 1);
        }
        LOG.info("using username: " + webUserName + ", password (shortened): " + pwShort);

        if(servletRequest!=null && servletRequest instanceof HttpServletRequest) {
          HttpSession httpSession=((HttpServletRequest)servletRequest).getSession(true);
          if(httpSession!=null) {
            httpSession.setAttribute("de.dumischbaenger.jetty.username", webUserName);
            httpSession.setAttribute("de.dumischbaenger.jetty.password", webCredential);
            LOG.info("session catched: " + httpSession.getId());
          }
          servletRequest.setAttribute("de.dumischbaenger.jetty.username", webUserName);
          servletRequest.setAttribute("de.dumischbaenger.jetty.password", webCredential);
          
          LOG.info("servlet request catched");
        }
      }

      if (webUserName == null || webCredential == null) {
        setAuthenticated(false);
        return isAuthenticated();
      }

      boolean authed = false;

      if (_forceBindingLogin) {
        authed = bindingLogin(webUserName, webCredential);
      } else {
        // This sets read and the credential
        UserInfo userInfo = getUserInfo(webUserName);

        if (userInfo == null) {
          setAuthenticated(false);
          return false;
        }

        setCurrentUser(new JAASUserInfo(userInfo));

        if (webCredential instanceof String)
          authed = credentialLogin(Credential.getCredential((String) webCredential));
        else
          authed = credentialLogin(webCredential);
      }

      // only fetch roles if authenticated
      if (authed)
        getCurrentUser().fetchRoles();

      return authed;
    } catch (UnsupportedCallbackException e) {
      throw new LoginException("Error obtaining callback information.");
    } catch (IOException e) {
      if (_debug) {
        LOG.info(e);
      }
      throw new LoginException("IO Error performing login.");
    } catch (AuthenticationException e) {
      if (_debug) {
        LOG.info(e);
      }
      return false;
    } catch (LoginException e) {
      throw e;
    } catch (Exception e) {
      if (_debug)
        LOG.info(e);
      throw new LoginException("Error obtaining user info");
    }
  }

  /**
   * password supplied authentication check
   *
   * @param webCredential
   *          the web credential
   * @return true if authenticated
   * @throws LoginException
   *           if unable to login
   */
  protected boolean credentialLogin(Object webCredential) throws LoginException {
    setAuthenticated(getCurrentUser().checkCredential(webCredential));
    return isAuthenticated();
  }

  /**
   * binding authentication check This method of authentication works only if the
   * user branch of the DIT (ldap tree) has an ACI (access control instruction)
   * that allow the access to any user or at least for the user that logs in.
   *
   * @param username
   *          the user name
   * @param password
   *          the password
   * @return true always
   * @throws LoginException
   *           if unable to bind the login
   */
  public boolean bindingLogin(String username, Object password) throws LoginException {
    SearchResult searchResult = findUser(username);

    String userDn = searchResult.getNameInNamespace();

    LOG.info("Attempting authentication: " + userDn);

    Hashtable<Object, Object> environment = getEnvironment();

    if (userDn == null || "".equals(userDn)) {
      throw new FailedLoginException("username may not be empty");
    }
    environment.put(Context.SECURITY_PRINCIPAL, userDn);
    // RFC 4513 section 6.3.1, protect against ldap server implementations that
    // allow successful binding on empty passwords
    if (password == null || "".equals(password)) {
      throw new FailedLoginException("password may not be empty");
    }
    environment.put(Context.SECURITY_CREDENTIALS, password);

    try {
      DirContext dirContext = new InitialDirContext(environment);
      List<String> roles = getUserRolesByDn(dirContext, userDn);

      UserInfo userInfo = new UserInfo(username, null, roles);
      setCurrentUser(new JAASUserInfo(userInfo));
      setAuthenticated(true);

      return true;
    } catch (javax.naming.AuthenticationException e) {
      throw new FailedLoginException(e.getMessage());
    } catch (NamingException e) {
      throw new FailedLoginException(e.getMessage());
    }
  }

  private SearchResult findUser(String username) throws LoginException {
    String filter = "(&(objectClass={0})({1}={2}))";

    if (LOG.isDebugEnabled())
      LOG.debug(
          "Searching for user " + username + " with filter: \'" + filter + "\'" + " from base dn: " + _userBaseDn);

    Object[] filterArguments = new Object[] { _userObjectClass, _userIdAttribute, username };

    return findUser(_rootContext, filter, filterArguments);
  }

  private SearchResult findUser(DirContext dirContext, String filter, Object[] filterArguments) throws LoginException {
    SearchControls ctls = new SearchControls();
    ctls.setDerefLinkFlag(true);
    ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

    NamingEnumeration<SearchResult> results;
    try {
      results = _rootContext.search(_userBaseDn, filter, filterArguments, ctls);
    } catch (NamingException ne) {
      throw new FailedLoginException(ne.getMessage());
    }

    if (LOG.isDebugEnabled())
      LOG.debug("Found user?: " + results.hasMoreElements());

    if (!results.hasMoreElements())
      throw new FailedLoginException("User not found.");

    SearchResult searchResult = (SearchResult) results.nextElement();
    if (results.hasMoreElements())
      throw new FailedLoginException("Search result contains ambiguous entries");

    return searchResult;
  }

  /**
   * Init LoginModule.
   * <p>
   * Called once by JAAS after new instance is created.
   *
   * @param subject
   *          the subect
   * @param callbackHandler
   *          the callback handler
   * @param sharedState
   *          the shared state map
   * @param options
   *          the option map
   */
  @Override
  public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
      Map<String, ?> options) {
    super.initialize(subject, callbackHandler, sharedState, options);

    _hostname = (String) options.get("hostname");
    _port = Integer.parseInt((String) options.get("port"));
    _contextFactory = (String) options.get("contextFactory");
    _bindDn = (String) options.get("bindDn");
    _bindPassword = (String) options.get("bindPassword");
    _authenticationMethod = (String) options.get("authenticationMethod");

    _userBaseDn = (String) options.get("userBaseDn");

    _roleBaseDn = (String) options.get("roleBaseDn");

    if (options.containsKey("forceBindingLogin")) {
      _forceBindingLogin = Boolean.parseBoolean((String) options.get("forceBindingLogin"));
    }

    if (options.containsKey("useLdaps")) {
      _useLdaps = Boolean.parseBoolean((String) options.get("useLdaps"));
    }

    _userObjectClass = getOption(options, "userObjectClass", _userObjectClass);
    _userRdnAttribute = getOption(options, "userRdnAttribute", _userRdnAttribute);
    _userIdAttribute = getOption(options, "userIdAttribute", _userIdAttribute);
    _userPasswordAttribute = getOption(options, "userPasswordAttribute", _userPasswordAttribute);
    _roleObjectClass = getOption(options, "roleObjectClass", _roleObjectClass);
    _roleMemberAttribute = getOption(options, "roleMemberAttribute", _roleMemberAttribute);
    _roleNameAttribute = getOption(options, "roleNameAttribute", _roleNameAttribute);
    _debug = Boolean.parseBoolean(String.valueOf(getOption(options, "debug", Boolean.toString(_debug))));

    try {
      _rootContext = new InitialDirContext(getEnvironment());
    } catch (NamingException ex) {
      throw new IllegalStateException("Unable to establish root context", ex);
    }
  }

  @Override
  public boolean commit() throws LoginException {
    try {
      _rootContext.close();
    } catch (NamingException e) {
      throw new LoginException("error closing root context: " + e.getMessage());
    }

    return super.commit();
  }

  @Override
  public boolean abort() throws LoginException {
    try {
      _rootContext.close();
    } catch (NamingException e) {
      throw new LoginException("error closing root context: " + e.getMessage());
    }

    return super.abort();
  }

  private String getOption(Map<String, ?> options, String key, String defaultValue) {
    Object value = options.get(key);

    if (value == null) {
      return defaultValue;
    }

    return (String) value;
  }

  /**
   * get the context for connection
   *
   * @return the environment details for the context
   */
  public Hashtable<Object, Object> getEnvironment() {
    Properties env = new Properties();

    env.put(Context.INITIAL_CONTEXT_FACTORY, _contextFactory);

    if (_hostname != null) {
      env.put(Context.PROVIDER_URL,
          (_useLdaps ? "ldaps://" : "ldap://") + _hostname + (_port == 0 ? "" : ":" + _port) + "/");
    }

    if (_authenticationMethod != null) {
      env.put(Context.SECURITY_AUTHENTICATION, _authenticationMethod);
    }

    if (_bindDn != null) {
      env.put(Context.SECURITY_PRINCIPAL, _bindDn);
    }

    if (_bindPassword != null) {
      env.put(Context.SECURITY_CREDENTIALS, _bindPassword);
    }

    return env;
  }

  public static String convertCredentialLdapToJetty(String encryptedPassword) {
    if (encryptedPassword == null) {
      return null;
    }

    if (encryptedPassword.toUpperCase(Locale.ENGLISH).startsWith("{MD5}")) {
      String src = encryptedPassword.substring("{MD5}".length(), encryptedPassword.length());
      return "MD5:" + base64ToHex(src);
    }

    if (encryptedPassword.toUpperCase(Locale.ENGLISH).startsWith("{CRYPT}")) {
      return "CRYPT:" + encryptedPassword.substring("{CRYPT}".length(), encryptedPassword.length());
    }

    return encryptedPassword;
  }

  private static String base64ToHex(String src) {
    byte[] bytes = B64Code.decode(src);
    return TypeUtil.toString(bytes, 16);
  }

  private static String hexToBase64(String src) {
    byte[] bytes = TypeUtil.fromHexString(src);
    return new String(B64Code.encode(bytes));
  }
}