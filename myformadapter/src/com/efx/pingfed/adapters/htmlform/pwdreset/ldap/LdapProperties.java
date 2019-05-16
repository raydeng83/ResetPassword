package com.efx.pingfed.adapters.htmlform.pwdreset.ldap;

public class LdapProperties {

    private String ldapId;
    private String searchBaseDN;
    private String searchFilter;
    private String firstName;
    private String lastName;
    private String mail;
    private String memberOf;
    private String serviceDeskFilter;
    private String mfaGroupDN;
    private String authenticationMethod;
    private boolean useSSL;
    private String principal;
    private String serverUrl;
    private String credentials;
    private String softTokenGroup;
    private String hardTokenGroup;
    private String mobile;

    public String getLdapId() {
        return ldapId;
    }

    public void setLdapId(String ldapId) {
        this.ldapId = ldapId;
    }

    public String getSearchBaseDN() {
        return searchBaseDN;
    }

    public void setSearchBaseDN(String searchBaseDN) {
        this.searchBaseDN = searchBaseDN;
    }

    public String getSearchFilter() {
        return searchFilter;
    }

    public void setSearchFilter(String searchFilter) {
        this.searchFilter = searchFilter;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getMail() {
        return mail;
    }

    public void setMail(String mail) {
        this.mail = mail;
    }

    public String getMemberOf() {
        return memberOf;
    }

    public void setMemberOf(String memberOf) {
        this.memberOf = memberOf;
    }

    public String getServiceDeskFilter() {
        return serviceDeskFilter;
    }

    public void setServiceDeskFilter(String serviceDeskFilter) {
        this.serviceDeskFilter = serviceDeskFilter;
    }

    public String getMfaGroupDN() {
        return mfaGroupDN;
    }

    public void setMfaGroupDN(String mfaGroupDN) {
        this.mfaGroupDN = mfaGroupDN;
    }

    public String getAuthenticationMethod() {
        return authenticationMethod;
    }

    public void setAuthenticationMethod(String authenticationMethod) {
        this.authenticationMethod = authenticationMethod;
    }

    public boolean isUseSSL() {
        return useSSL;
    }

    public void setUseSSL(boolean useSSL) {
        this.useSSL = useSSL;
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(String serverUrl) {
        this.serverUrl = serverUrl;
    }

    public String getCredentials() {
        return credentials;
    }

    public void setCredentials(String credentials) {
        this.credentials = credentials;
    }

    public String getSoftTokenGroup() {
        return softTokenGroup;
    }

    public void setSoftTokenGroup(String softTokenGroup) {
        this.softTokenGroup = softTokenGroup;
    }

    public String getHardTokenGroup() {
        return hardTokenGroup;
    }

    public void setHardTokenGroup(String hardTokenGroup) {
        this.hardTokenGroup = hardTokenGroup;
    }

    public String getMobile() {
        return mobile;
    }

    public void setMobile(String mobile) {
        this.mobile = mobile;
    }

    public void loadProperties() {
        ldapId = "WIN-QOAIQF1BG1E.example.com";
        searchBaseDN = "CN=Users,DC=example,DC=com";
        searchFilter = "sAMAccountName=${username}";
        principal = "CN=Administrator,CN=Users,DC=example,DC=com";
        serverUrl = "https://localhost:636";
        useSSL = true;
        firstName = "givenName";
        lastName = "sn";
        mail = "mail";
        mobile = "mobile";
    }
}
