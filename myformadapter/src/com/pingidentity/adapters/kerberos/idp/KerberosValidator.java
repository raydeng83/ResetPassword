package com.pingidentity.adapters.kerberos.idp;

import com.pingidentity.access.KerberosRealmAccessor;
import com.pingidentity.common.util.KerberosUtil;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.sourceid.saml20.domain.KerberosRealm;









public class KerberosValidator
{
  private static Logger log = LogManager.getLogger(KerberosValidator.class);
  
  private String kerberosRealmId = null;
  private static final Object locker = new Object();
  







  public void setKerberosRealmId(String kerberosRealmId)
  {
    this.kerberosRealmId = kerberosRealmId;
  }
  







  public KerberosSubject validateTGS(byte[] tgs)
    throws com.pingidentity.adapters.kerberos.exception.KerberosException
  {
    SpnegoParser spnegoParser = new SpnegoParser();
    String userNameWithDomain = null;
    
    String domainName = null;
    Set<String> sids = new HashSet();
    

    try
    {
      spnegoParser.parse(tgs);
      byte[] token = spnegoParser.getMechanismToken();
      
      KerberosRealmAccessor kerberosRealmAccessor = new KerberosRealmAccessor();
      KerberosRealm kerberosRealm = kerberosRealmAccessor.getKerberosRealm(this.kerberosRealmId);
      
      try
      {
        synchronized (locker)
        {
          KerberosUtil kerberosUtil = new KerberosUtil(kerberosRealm);
          userNameWithDomain = kerberosUtil.validateTicket(token);
          try {
            sids = kerberosUtil.extractSids(token);
          }
          catch (com.pingidentity.common.security.KerberosException e)
          {
            log.warn("Couldn't extract SIDs from Kerberos token. " + e.getMessage());
          }
        }
      }
      catch (com.pingidentity.common.security.KerberosException e)
      {
        log.error("Unable to login to KDC, Domain/Realm=" + kerberosRealm.getKerberosRealmName() + " Username=" + kerberosRealm.getKerberosUsername());
        throw new com.pingidentity.adapters.kerberos.exception.KerberosException(e, true, false);
      }
      
      String userName = userNameWithDomain;
      
      log.debug("userNameWithDomain retrieved succesfully.");
      
      if (userNameWithDomain != null)
      {
        int idx = userNameWithDomain.lastIndexOf("@");
        if (idx != -1)
        {
          userName = userNameWithDomain.substring(0, idx);
          domainName = userNameWithDomain.substring(idx + 1, userNameWithDomain.length());
          if ((StringUtils.isNotEmpty(domainName)) && 
            (!domainName.equalsIgnoreCase(kerberosRealm.getKerberosRealmName())))
          {
            if (kerberosRealmAccessor.getKerberosRealmByName(domainName) != null)
            {
              throw new com.pingidentity.adapters.kerberos.exception.KerberosException("A Domain/Realm mismatch occurred, ensure you're using the correct adapter instance", false, false);
            }
            

            log.debug("Using inter-domain trust relationship for Domain/Realm: " + domainName);
          }
        }
      }
      

      log.debug("KerberosSubject created successfully.");
      
      return new KerberosSubject(userName, domainName, sids);
    }
    catch (IOException e)
    {
      throw new com.pingidentity.adapters.kerberos.exception.KerberosException(e, true, false);
    }
    catch (IndexOutOfBoundsException e)
    {
      log.error("IndexException: Unable to retrieve UserName/Domain from userId=" + userNameWithDomain);
      throw new com.pingidentity.adapters.kerberos.exception.KerberosException(e, true, false);
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\kerberos\idp\KerberosValidator.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */