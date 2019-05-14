package com.pingidentity.adapters.kerberos.idp;

import com.pingidentity.adapters.kerberos.exception.KerberosException;
import com.pingidentity.adapters.kerberos.utils.AdapterSession;
import com.pingidentity.adapters.kerberos.utils.AdapterSessionFactory;
import com.pingidentity.sdk.AuthnAdapterResponse;
import com.pingidentity.sdk.AuthnAdapterResponse.AUTHN_STATUS;
import com.pingidentity.sdk.IdpAuthenticationAdapterV2;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.slf4j.MDC;
import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.FieldList;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.kerberos.KerberosRealmFieldDescriptor;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthnAdapterDescriptor;





















public class KerberosAuthenticationAdapter
  implements IdpAuthenticationAdapterV2
{
  private static final Logger log = LogManager.getLogger(KerberosAuthenticationAdapter.class);
  
  private static final String SENT_AUTHN_REQUEST = "SENT_AUTHN_REQUEST";
  
  private static final String NTLMSSP = "NTLMSSP";
  
  private static final String META_REFRESH_TEMPLATE = "meta.refresh.template.html";
  
  private static final String KERBEROS_ERROR_TEMPLATE = "kerberos.error.template.html";
  
  private static final String PARAM_PREFIX = "com.pingidentity.adapter.input.parameter.";
  
  private KerberosValidator krbValidator;
  
  private AdapterConfigurationGuiDescriptor adapterConfGuiDesc;
  
  protected IdpAuthnAdapterDescriptor adapterDescriptor;
  
  protected String errorRedirectUrl;
  
  protected boolean errorTemplate;
  
  protected String authnCtxValue;
  
  protected String domainId;
  

  public KerberosAuthenticationAdapter()
    throws AuthnAdapterException
  {
    Set<String> attrNames = new HashSet();
    attrNames.add("Username");
    attrNames.add("Domain/Realm Name");
    attrNames.add("SIDs");
    

    this.adapterDescriptor = new IdpAuthnAdapterDescriptor(this, "Kerberos Adapter", attrNames, false, initConfGuiDesc(), false);
  }
  


  private AdapterConfigurationGuiDescriptor initConfGuiDesc()
  {
    this.adapterConfGuiDesc = new AdapterConfigurationGuiDescriptor();
    this.adapterConfGuiDesc.setDescription("This adapter uses Kerberos to leverage a AD Domain/Realm login for Web authentication.");
    
    KerberosRealmFieldDescriptor kerberosRealmFieldDescriptor = new KerberosRealmFieldDescriptor("Domain/Realm Name", "Select the Domain/Realm Name configured via Active Directory Domains/Kerberos Realms.  To Add/Modify/Remove a Domain/Realm, use the Manage Active Directory Domains/Kerberos Realms button at the bottom of this screen.");
    kerberosRealmFieldDescriptor.addValidator(Constants.REQUIRED_VALIDATOR);
    this.adapterConfGuiDesc.addField(kerberosRealmFieldDescriptor);
    

    TextFieldDescriptor redirectUrlField = new TextFieldDescriptor("Error URL Redirect", "The URL where you want the user redirected when there are errors.");
    redirectUrlField.addValidator(Constants.HTTP_URL_VALIDATOR, true);
    this.adapterConfGuiDesc.addField(redirectUrlField);
    

    CheckBoxFieldDescriptor errorTemplateKerbOnlyField = new CheckBoxFieldDescriptor("Error Template", "Provides a template (<pf_home>/server/default/conf/template/kerberos.error.template.html) to standardize browser behavior when authentication fails.");
    errorTemplateKerbOnlyField.setDefaultValue(false);
    this.adapterConfGuiDesc.addAdvancedField(errorTemplateKerbOnlyField);
    
    TextFieldDescriptor actx = new TextFieldDescriptor("Authentication Context Value", "Additional information provided to the SP to assess the level of confidence in the assertion.");
    this.adapterConfGuiDesc.addAdvancedField(actx);
    
    return this.adapterConfGuiDesc;
  }
  


  public void configure(Configuration conf)
  {
    this.domainId = conf.getFieldValue("Domain/Realm Name");
    
    this.errorRedirectUrl = conf.getFieldValue("Error URL Redirect");
    
    FieldList advancedFields = conf.getAdvancedFields();
    this.authnCtxValue = advancedFields.getFieldValue("Authentication Context Value");
    this.errorTemplate = advancedFields.getBooleanFieldValue("Error Template");
  }
  

  public IdpAuthnAdapterDescriptor getAdapterDescriptor()
  {
    return this.adapterDescriptor;
  }
  







  private void errorRedirect(HttpServletResponse response, String resumeUrl, String errorMessage)
    throws IOException, AuthnAdapterException
  {
    log.debug("KerberoslookupAuthN: Redirecting to " + this.errorRedirectUrl);
    
    if ((this.errorRedirectUrl != null) && (!"".equals(this.errorRedirectUrl.trim())))
    {
      if (!this.errorRedirectUrl.contains("?"))
      {
        response.sendRedirect(this.errorRedirectUrl + "?resumeURL=" + resumeUrl + "&errorMessage=" + errorMessage);
      }
      else
      {
        response.sendRedirect(this.errorRedirectUrl + "&resumeURL=" + resumeUrl + "&errorMessage=" + errorMessage);
      }
      
    }
    else {
      MDC.put("description", errorMessage);
    }
  }
  







  private Map<String, Object> getAuthnIdentifiers(KerberosSubject kerberosSubject)
  {
    Map<String, Object> returnMap = new HashMap();
    returnMap.put("Username", kerberosSubject.getUsername());
    returnMap.put("Domain/Realm Name", kerberosSubject.getDomain());
    returnMap.put("SIDs", new AttributeValue(kerberosSubject.getSids()));
    
    if ((this.authnCtxValue != null) && (!this.authnCtxValue.equals("")))
    {
      returnMap.put("org.sourceid.saml20.adapter.idp.authn.authnCtx", this.authnCtxValue);
    }
    
    return returnMap;
  }
  












  private KerberosSubject isUserValid(String tokenValue, String kerberosRealmId)
    throws AuthnAdapterException
  {
    try
    {
      tokenBytesArr = Base64.decodeBase64(tokenValue.getBytes("UTF-8"));
    }
    catch (UnsupportedEncodingException e1) {
      byte[] tokenBytesArr;
      throw new RuntimeException(e1);
    }
    
    try
    {
      byte[] tokenBytesArr;
      this.krbValidator = new KerberosValidator();
      this.krbValidator.setKerberosRealmId(kerberosRealmId);
      subj = this.krbValidator.validateTGS(tokenBytesArr);
    }
    catch (KerberosException e) {
      KerberosSubject subj;
      String reason = "";
      if (e.isKdcLoginProblem())
      {
        reason = "KdcLoginProblem";
      }
      else if (e.isTgsValidationProblem())
      {
        reason = "TgsValidationProblem";
      }
      
      reason = reason + ": Could not validate Kerberos TGT, please make sure the service principal name is set correctly and the credential cache on client machine is refreshed by re-login to the windows domain.";
      
      log.error(reason, e);
      
      throw new AuthnAdapterException(reason, e);
    }
    KerberosSubject subj;
    return subj;
  }
  





  public boolean logoutAuthN(Map map, HttpServletRequest httpservletrequest, HttpServletResponse httpservletresponse, String s)
    throws AuthnAdapterException, IOException
  {
    log.debug(" + KerberoslogoutAuthN");
    log.debug(" - KerberoslogoutAuthN return: true");
    return true;
  }
  

  public Map<String, Object> getAdapterInfo()
  {
    return null;
  }
  


  public Map lookupAuthN(HttpServletRequest request, HttpServletResponse response, String entityId, AuthnPolicy authnpolicy, String resumeUrl)
    throws AuthnAdapterException, IOException
  {
    Map<String, Object> inParameters = new HashMap();
    
    inParameters.put("com.pingidentity.adapter.input.parameter.partner.entityid", entityId);
    inParameters.put("com.pingidentity.adapter.input.parameter.resume.path", resumeUrl);
    inParameters.put("com.pingidentity.adapter.input.parameter.authn.policy", authnpolicy);
    
    AuthnAdapterResponse responseMap = lookupAuthN(request, response, inParameters);
    
    return responseMap.getAttributeMap();
  }
  






  public AuthnAdapterResponse lookupAuthN(HttpServletRequest request, HttpServletResponse response, Map<String, Object> inParameters)
    throws AuthnAdapterException, IOException
  {
    log.debug("+ KerberoslookupAuthN");
    
    AuthnAdapterResponse adapterResponse = new AuthnAdapterResponse();
    
    AdapterSession adapterSession = AdapterSessionFactory.getAdapterSession();
    


    String resumeUrl = inParameters.get("com.pingidentity.adapter.input.parameter.resume.path") == null ? "" : inParameters.get("com.pingidentity.adapter.input.parameter.resume.path").toString();
    
    Map<String, Object> ids = null;
    




    if (!request.getRequestURI().endsWith(resumeUrl))
    {
      log.debug("\tRequest doesn't end with ResumeUrl. Redirect to ResumeURL: " + resumeUrl + "?" + request
        .getQueryString());
      String queryString = "";
      
      response.sendRedirect(resumeUrl + queryString);
      adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.IN_PROGRESS);
      return adapterResponse;
    }
    

    String authHeader = request.getHeader("Authorization");
    




    if (authHeader == null)
    {
      log.debug("\tWWW-Authenticate header not found");
      
      response.setHeader("WWW-Authenticate", "Negotiate");
      log.debug("\tWWW-Authenticate: Negotiate requested from client.");
      
      response.setStatus(401);
      
      String sentAuthenticateHeader = (String)adapterSession.getAttribute("SENT_AUTHN_REQUEST", request, response);
      
      if ((sentAuthenticateHeader != null) && (Boolean.parseBoolean(sentAuthenticateHeader)))
      {
        adapterSession.removeAttribute("SENT_AUTHN_REQUEST", request, response);
        log.debug("\tLogin Failed: Page refreshed without responding to WWW-Authenticate header.");
        errorRedirect(response, resumeUrl, "Logon failed.");
        adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.FAILURE);
        return adapterResponse;
      }
      
      adapterSession.setAttribute("SENT_AUTHN_REQUEST", Boolean.TRUE.toString(), request, response);
      




      Object isComposite = inParameters.get("com.pingidentity.adapter.input.parameter.chained.attributes");
      if (isComposite != null)
      {
        TemplateRendererUtil.render(request, response, "meta.refresh.template.html", new HashMap());
      }
      else if (this.errorTemplate)
      {
        Map<String, Object> params = new HashMap();
        params.put("resumeUrl", resumeUrl);
        TemplateRendererUtil.render(request, response, "kerberos.error.template.html", params);
      }
      




      adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.IN_PROGRESS);
      response.flushBuffer();
      return adapterResponse;
    }
    


    adapterSession.removeAttribute("SENT_AUTHN_REQUEST", request, response);
    



    String tokenPrefix = "";
    

    String tokenValue = "";
    boolean invalidToken = false;
    
    tokenPrefix = "Negotiate ";
    tokenValue = authHeader.substring(tokenPrefix.length(), authHeader.length());
    
    byte[] tokenBytesArr = Base64.decodeBase64(tokenValue.getBytes("UTF-8"));
    
    invalidToken = isInvalidKerberosToken(tokenBytesArr);
    

    if (invalidToken)
    {
      adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.FAILURE);
      
      String tokenString = new String(tokenBytesArr, StandardCharsets.UTF_8);
      if (tokenString.startsWith("NTLMSSP"))
      {
        handleNTLMerror(response, resumeUrl);
        return adapterResponse;
      }
      
      log.error("Invalid token received: " + authHeader);
      throw new AuthnAdapterException("Invalid token received.");
    }
    
    log.debug("Token Type = KERBEROS");
    log.debug("" + authHeader);
    
    boolean kerberosLogonFailed = false;
    try
    {
      KerberosSubject subj = isUserValid(tokenValue, this.domainId);
      if ((subj != null) && (subj.getUsername() != null))
      {
        ids = getAuthnIdentifiers(subj);
      }
      else
      {
        log.error("\tInvalid user.");
        kerberosLogonFailed = true;
      }
      
    }
    catch (AuthnAdapterException e)
    {
      log.error("\t" + e.getMessage());
      kerberosLogonFailed = true;
      




      Object isComposite = inParameters.get("com.pingidentity.adapter.input.parameter.chained.attributes");
      if (isComposite != null)
      {
        adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.FAILURE);
        log.debug("- KerberoslookupAuthN return");
        return adapterResponse;
      }
      if (this.errorTemplate)
      {
        Map<String, Object> params = new HashMap();
        params.put("resumeUrl", resumeUrl);
        TemplateRendererUtil.render(request, response, "kerberos.error.template.html", params);
        log.debug("- KerberoslookupAuthN return");
        adapterResponse.setAttributeMap(ids);
        adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.FAILURE);
        return adapterResponse;
      }
    }
    
    if (kerberosLogonFailed)
    {
      handleNTLMerror(response, resumeUrl);
      adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.FAILURE);
      return adapterResponse;
    }
    


    log.debug("- KerberoslookupAuthN return");
    
    adapterResponse.setAttributeMap(ids);
    adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.SUCCESS);
    


    return adapterResponse;
  }
  










  private boolean isInvalidKerberosToken(byte[] tokenBytesArr)
    throws UnsupportedEncodingException
  {
    boolean invalidToken = false;
    switch (tokenBytesArr[0])
    {
    case 96: 
      break;
    case -95: 
      break;
    default: 
      invalidToken = true;
    }
    
    return invalidToken;
  }
  
  private void handleNTLMerror(HttpServletResponse response, String resumeUrl)
    throws IOException, AuthnAdapterException
  {
    log.error("Kerberos authentication is selected.  NTLM not allowed.");
    errorRedirect(response, resumeUrl, "Kerberos authentication is selected, NTLM not allowed.");
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\kerberos\idp\KerberosAuthenticationAdapter.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */