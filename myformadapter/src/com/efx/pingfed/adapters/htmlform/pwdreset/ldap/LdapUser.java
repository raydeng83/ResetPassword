package com.efx.pingfed.adapters.htmlform.pwdreset.ldap;

public class LdapUser {
    private String username;
    private String firstName;
    private String lastName;
    private String emailAddress;
    private boolean softTokenUser;
    private boolean hardTokenUser;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
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

    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public boolean isSoftTokenUser() {
        return softTokenUser;
    }

    public void setSoftTokenUser(boolean softTokenUser) {
        this.softTokenUser = softTokenUser;
    }

    public boolean isHardTokenUser() {
        return hardTokenUser;
    }

    public void setHardTokenUser(boolean hardTokenUser) {
        this.hardTokenUser = hardTokenUser;
    }
}
