package com.pingidentity.adapters.httpbasic.idp;

import com.pingidentity.access.PasswordCredentialValidatorAccessor;
import com.pingidentity.adapters.httpbasic.config.HttpBasicGuiConfiguration;
import com.pingidentity.common.util.B64;
import com.pingidentity.common.util.LogGuard;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.common.Util;
import org.sourceid.common.VersionUtil;
import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthenticationAdapter;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthnAdapterDescriptor;
import org.sourceid.saml20.adapter.state.TransactionalStateSupport;
import org.sourceid.websso.AuditLogger;




public class HttpBasicIdpAuthnAdapter
  implements IdpAuthenticationAdapter
{
  private final Log log = LogFactory.getLog(getClass());
  private static final String ADAPTER_NAME = "HTTP Basic IdP Adapter";
  private final HttpBasicGuiConfiguration httpBasicGuiConfiguration = new HttpBasicGuiConfiguration();
  
  private String realm = null;
  private int challengeRetries;
  private final List<String> pwdCrdVal = new ArrayList();
  

  private final String SESSION_KEY_CHALLENGED_USER = getClass().getSimpleName() + ":challenged";
  


  public Map lookupAuthN(HttpServletRequest req, HttpServletResponse resp, String partnerSpEntityId, AuthnPolicy authnPolicy, String resumeUrl)
    throws IOException
  {
    String authHeader = req.getHeader("Authorization");
    boolean hasBasicAuthHeader = (authHeader != null) && (authHeader.toLowerCase().startsWith("basic"));
    
    if ((!req.getRequestURI().endsWith(resumeUrl)) && (!hasBasicAuthHeader))
    {
      resp.sendRedirect(resumeUrl);
    }
    else
    {
      TransactionalStateSupport txStateSupport = new TransactionalStateSupport(resumeUrl);
      

      if (!hasBasicAuthHeader)
      {
        challengeWithBasic(req, resp, resumeUrl, authnPolicy, txStateSupport);
      }
      else
      {
        authHeader = authHeader.substring(authHeader.indexOf(' ') + 1);
        authHeader = B64.decodeToString(authHeader);
        int i = authHeader.indexOf(':');
        String username = authHeader.substring(0, i);
        String password = authHeader.substring(i + 1);
        
        Map authnIds = null;
        
        AuditLogger.setUserName(LogGuard.encode(username));
        



        for (String pcv : this.pwdCrdVal)
        {
          try
          {
            PasswordCredentialValidator credentialValidator = new PasswordCredentialValidatorAccessor().getPasswordCredentialValidator(pcv);
            authnIds = credentialValidator.processPasswordCredential(username, password);
            if (!Util.isEmpty(authnIds))
            {
              AuditLogger.setPcvId(pcv);
              break;
            }
            
          }
          catch (Exception e)
          {
            this.log.warn(e.getMessage());
          }
        }
        
        if (Util.isEmpty(authnIds))
        {
          int numberOfChallenges = getNumChallenges(req, resp, txStateSupport);
          if (numberOfChallenges < this.challengeRetries)
          {
            challengeWithBasic(req, resp, resumeUrl, authnPolicy, txStateSupport);
          }
          else
          {
            txStateSupport.removeAttribute(this.SESSION_KEY_CHALLENGED_USER, req, resp);
          }
        }
        else
        {
          txStateSupport.removeAttribute(this.SESSION_KEY_CHALLENGED_USER, req, resp);
          return authnIds;
        }
      }
    }
    
    return null;
  }
  

  public void configure(Configuration configuration)
  {
    this.realm = configuration.getFieldValue("Realm");
    this.challengeRetries = Integer.parseInt(configuration.getFieldValue("Challenge Retries"));
    
    for (Row row : configuration.getTable("Credential Validators").getRows())
    {
      this.pwdCrdVal.add(row.getFieldValue("Password Credential Validator Instance"));
    }
  }
  
  public String getRealm()
  {
    return this.realm;
  }
  

  public boolean logoutAuthN(Map authnIdentifiers, HttpServletRequest req, HttpServletResponse resp, String resumePath)
    throws AuthnAdapterException, IOException
  {
    return true;
  }
  

  public IdpAuthnAdapterDescriptor getAdapterDescriptor()
  {
    return new IdpAuthnAdapterDescriptor(this, "HTTP Basic IdP Adapter", this.httpBasicGuiConfiguration.createAttributeContract(), false, this.httpBasicGuiConfiguration
      .getGuiDescriptor(), false, 
      VersionUtil.getVersion());
  }
  
  private void challengeWithBasic(HttpServletRequest req, HttpServletResponse resp, String resumeUrl, AuthnPolicy authnPolicy, TransactionalStateSupport transactionalStateSupport)
    throws IOException
  {
    if (!req.getRequestURI().endsWith(resumeUrl))
    {
      resp.sendRedirect(resumeUrl);
    }
    else if (authnPolicy.allowUserInteraction())
    {
      int numberOfChallenges = getNumChallenges(req, resp, transactionalStateSupport);
      transactionalStateSupport.setAttribute(this.SESSION_KEY_CHALLENGED_USER, String.valueOf(numberOfChallenges + 1), req, resp);
      
      resp.setHeader("WWW-Authenticate", "basic realm=\"" + getRealm() + "\"");
      resp.sendError(401);
    }
  }
  


  private int getNumChallenges(HttpServletRequest req, HttpServletResponse resp, TransactionalStateSupport transactionalStateSupport)
  {
    Object sessionAttr = transactionalStateSupport.getAttribute(this.SESSION_KEY_CHALLENGED_USER, req, resp);
    int numberOfChallenges = 0;
    if (sessionAttr != null)
    {
      if ((sessionAttr instanceof Integer))
      {
        numberOfChallenges = ((Integer)sessionAttr).intValue();
      }
      else if ((sessionAttr instanceof String))
      {
        try
        {
          numberOfChallenges = Integer.parseInt((String)sessionAttr);
        }
        catch (NumberFormatException localNumberFormatException) {}
      }
    }
    

    return numberOfChallenges;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\httpbasic\idp\HttpBasicIdpAuthnAdapter.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */