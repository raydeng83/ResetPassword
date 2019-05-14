package com.pingidentity.adapters.kerberos.idp;

import java.util.Set;










public class KerberosSubject
{
  private final String username;
  private final String domain;
  private final Set<String> sids;
  
  public KerberosSubject(String username, String domain, Set<String> sids)
  {
    this.username = username;
    this.domain = domain;
    this.sids = sids;
  }
  



  public String getDomain()
  {
    return this.domain;
  }
  



  public String getUsername()
  {
    return this.username;
  }
  




  public Set<String> getSids()
  {
    return this.sids;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\kerberos\idp\KerberosSubject.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */