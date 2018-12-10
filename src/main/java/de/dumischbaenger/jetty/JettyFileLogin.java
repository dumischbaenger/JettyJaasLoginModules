package de.dumischbaenger.jetty;

import java.io.IOException;


// this work is based on https://github.com/eclipse/jetty.project/blob/jetty-9.4.x/jetty-jaas/src/main/java/org/eclipse/jetty/jaas/spi/PropertyFileLoginModule.java

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

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

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
import org.eclipse.jetty.jaas.spi.UserInfo;
import org.eclipse.jetty.security.PropertyUserStore;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;
import org.eclipse.jetty.util.security.Credential;

/**
* PropertyFileLoginModule
*/
public class JettyFileLogin extends AbstractLoginModule
{
public static final String DEFAULT_FILENAME = "realm.properties";

private static final Logger LOG = Log.getLogger(JettyFileLogin.class);

private static ConcurrentHashMap<String, PropertyUserStore> _propertyUserStores = new ConcurrentHashMap<String, PropertyUserStore>();

private int _refreshInterval = 0;
private String _filename = DEFAULT_FILENAME;



/**
 * Read contents of the configured property file.
 *
 * @see javax.security.auth.spi.LoginModule#initialize(javax.security.auth.Subject, javax.security.auth.callback.CallbackHandler, java.util.Map,
 *      java.util.Map)
 *      
 * @param subject the subject
 * @param callbackHandler the callback handler
 * @param sharedState the shared state map
 * @param options the options map
 */
@Override
public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options)
{
    super.initialize(subject,callbackHandler,sharedState,options);
    setupPropertyUserStore(options);
}

private void setupPropertyUserStore(Map<String, ?> options)
{
    parseConfig(options);

    if (_propertyUserStores.get(_filename) == null)
    {
        PropertyUserStore propertyUserStore = new PropertyUserStore();
        propertyUserStore.setConfig(_filename);

        PropertyUserStore prev = _propertyUserStores.putIfAbsent(_filename, propertyUserStore);
        if (prev == null)
        {
            LOG.debug("setupPropertyUserStore: Starting new PropertyUserStore. PropertiesFile: " + _filename + " refreshInterval: " + _refreshInterval);

            try
            {
                propertyUserStore.start();
            }
            catch (Exception e)
            {
                LOG.warn("Exception while starting propertyUserStore: ",e);
            }
        }
    }
}

private void parseConfig(Map<String, ?> options)
{
    String tmp = (String)options.get("file");
    _filename = (tmp == null? DEFAULT_FILENAME : tmp);
    tmp = (String)options.get("refreshInterval");
    _refreshInterval = (tmp == null?_refreshInterval:Integer.parseInt(tmp));
}

/**
 * 
 *
 * @param userName the user name
 * @throws Exception if unable to get the user information
 */
@Override
public UserInfo getUserInfo(String userName) throws Exception
{
    PropertyUserStore propertyUserStore = _propertyUserStores.get(_filename);
    if (propertyUserStore == null)
        throw new IllegalStateException("PropertyUserStore should never be null here!");
    
    LOG.debug("Checking PropertyUserStore "+_filename+" for "+userName);
    UserIdentity userIdentity = propertyUserStore.getUserIdentity(userName);
    if (userIdentity==null)
        return null;

    //TODO in future versions change the impl of PropertyUserStore so its not
    //storing Subjects etc, just UserInfo
    Set<Principal> principals = userIdentity.getSubject().getPrincipals();

    List<String> roles = new ArrayList<String>();

    for ( Principal principal : principals )
    {
        roles.add( principal.getName() );
    }

    Credential credential = (Credential)userIdentity.getSubject().getPrivateCredentials().iterator().next();
    LOG.debug("Found: " + userName + " in PropertyUserStore "+_filename);
    return new UserInfo(userName, credential, roles);
}

@Override
public Callback[] configureCallbacks() {
    Callback[] callbacks = new Callback[4];
    callbacks[0] = new NameCallback("Enter user name");
    callbacks[1] = new ObjectCallback();
    callbacks[2] = new PasswordCallback("Enter password", false); //only used if framework does not support the ObjectCallback
    callbacks[3] = new ServletRequestCallback();
	return callbacks;
}

/**
 * @see javax.security.auth.spi.LoginModule#login()
 * @return true if is authenticated, false otherwise
 * @throws LoginException if unable to login
 */
@Override
public boolean login() throws LoginException
{
    try
    {  
        if (isIgnored())
            return false;
        
        if (getCallbackHandler() == null)
            throw new LoginException ("No callback handler");

        Callback[] callbacks = configureCallbacks();
        getCallbackHandler().handle(callbacks);

        String webUserName = ((NameCallback) callbacks[0]).getName();
        Object webCredential = ((ObjectCallback) callbacks[1]).getObject();
        ServletRequest servletRequest=((ServletRequestCallback)callbacks[3]).getRequest();
        
        
        String pwShort = "unknown";
        if (webCredential!=null && webCredential instanceof String) {
          String pw = (String) webCredential;
          
          if(pw.length()>1) {
            pwShort = pw.charAt(0) + "..." + pw.charAt(pw.length() - 1);
          }
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

        
        
        
        
        
        if (webCredential == null)
            webCredential = ((PasswordCallback)callbacks[2]).getPassword(); //use standard PasswordCallback

        if ((webUserName == null) || (webCredential == null))
        {
            setAuthenticated(false);
            throw new FailedLoginException();
        }

        UserInfo userInfo = getUserInfo(webUserName);

        if (userInfo == null)
        {
            setAuthenticated(false);
            throw new FailedLoginException();
        }

        JAASUserInfo currentUser = new JAASUserInfo(userInfo);
        setCurrentUser(currentUser);
        setAuthenticated(currentUser.checkCredential(webCredential));
      
        if (isAuthenticated())
        {
            currentUser.fetchRoles();
            return true;
        }
        else
            throw new FailedLoginException();
    }
    catch (IOException e)
    {
        throw new LoginException (e.toString());
    }
    catch (UnsupportedCallbackException e)
    {
        throw new LoginException (e.toString());
    }
    catch (Exception e)
    {
        if (e instanceof LoginException)
            throw (LoginException)e;
        throw new LoginException (e.toString());
    }
}


}
