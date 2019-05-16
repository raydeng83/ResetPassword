package com.efx.pingfed.adapters.htmlform.pwdreset.ldap;


import com.pingidentity.access.DataSourceAccessor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.domain.datasource.info.LdapInfo;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.Arrays;
import java.util.Hashtable;

public class LdapOperation {

    private static LdapOperation instance;
    private final LdapProperties props;
    private static final Log logger = LogFactory.getLog(LdapOperation.class);
    private LdapInfo ldapInfo = null;

    private LdapOperation() {
        this.props = new LdapProperties();
        this.props.loadProperties();
        DataSourceAccessor dataSourceAccessor = new DataSourceAccessor();

        if(this.props.getLdapId() != null) {
            this.ldapInfo = dataSourceAccessor.getLdapInfo(this.props.getLdapId());
        } else {
            this.ldapInfo = null;
        }
    }

    public static LdapOperation getInstance() {
        if (instance == null) {
            instance = new LdapOperation();
        }
        return instance;
    }

    public LdapUser searchUser(String username) throws NamingException {
        DirContext context = getContext();
        props.setUsername(username);
        props.loadProperties();
        LdapUser user = null;
        String ldapFilter = null;
        ldapFilter = this.props.getSearchFilter();
        String[] returnAtrr = new String[]{
                this.props.getFirstName(), this.props.getLastName(), this.props.getMail(), this.props.getMobile()
        };
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(returnAtrr);
        NamingEnumeration<SearchResult> results = context.search(props.getSearchBaseDN(), ldapFilter, controls);
        SearchResult result = null;

        if(results.hasMoreElements()) {
            logger.info(username + " found in LDAP. Fetching user attributes " + Arrays.asList(returnAtrr));
            result = (SearchResult) results.next();
            if (result.getAttributes() != null) {
                user = new LdapUser();
                Attributes resultAttributes = result.getAttributes();
                if (resultAttributes.get(this.props.getFirstName()) != null) {
                    user.setFirstName( (String) resultAttributes.get(this.props.getFirstName()).get());
                }
                if (resultAttributes.get(this.props.getLastName()) != null) {
                    user.setLastName( (String) resultAttributes.get(this.props.getLastName()).get());
                }
                if (resultAttributes.get(this.props.getMail()) != null) {
                    user.setEmailAddress( (String) resultAttributes.get(this.props.getMail()).get());
                }
                if (resultAttributes.get(this.props.getMobile()) != null) {
                    user.setMobile( (String) resultAttributes.get(this.props.getMobile()).get());
                }
                user.setUsername(username);
            }
        }
        context.close();
        return user;
    }

    private DirContext getContext() throws NamingException {
        DirContext context = null;
        Hashtable<String, Object> env = new Hashtable<>();

        if(this.ldapInfo != null) {
            env.put(Context.SECURITY_AUTHENTICATION, this.ldapInfo.getAuthenticationMethod());
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            if(this.ldapInfo.isUseSSL()) {
                env.put(Context.SECURITY_PROTOCOL, "ssl");
            }
            env.put(Context.SECURITY_PRINCIPAL, this.ldapInfo.getPrincipal());
            env.put(Context.PROVIDER_URL, this.ldapInfo.getServerUrl());
            env.put(Context.SECURITY_CREDENTIALS, this.props.getCredentials());
        }
        context = new InitialDirContext(env);
        return context;
    }
}
