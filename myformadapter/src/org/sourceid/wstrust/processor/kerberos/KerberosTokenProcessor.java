package org.sourceid.wstrust.processor.kerberos;

import com.pingidentity.access.KerberosRealmAccessor;
import com.pingidentity.common.security.KerberosException;
import com.pingidentity.common.util.KerberosUtil;
import com.pingidentity.sdk.GuiConfigDescriptor;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.sourceid.config.ConfigurationException;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.kerberos.KerberosRealmFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.saml20.domain.KerberosRealm;
import org.sourceid.wstrust.model.BinarySecurityToken;
import org.sourceid.wstrust.plugin.TokenProcessingException;
import org.sourceid.wstrust.plugin.process.InvalidTokenException;
import org.sourceid.wstrust.plugin.process.TokenContext;
import org.sourceid.wstrust.plugin.process.TokenProcessor;
import org.sourceid.wstrust.plugin.process.TokenProcessorDescriptor;
























public class KerberosTokenProcessor
  implements TokenProcessor<BinarySecurityToken>
{
  private static final Logger log = LogManager.getLogger(KerberosTokenProcessor.class);
  
  public static final String TYPE = "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ";
  
  private static String TOKEN_PROCESSOR_NAME = "Kerberos Token Processor";
  private static final RequiredFieldValidator REQUIRED_VALIDATOR = new RequiredFieldValidator();
  
  private final TokenProcessorDescriptor tokenProcessorDescriptor;
  
  private String kerberosRealmName;
  
  public KerberosTokenProcessor()
  {
    GuiConfigDescriptor gui = new GuiConfigDescriptor(TOKEN_PROCESSOR_NAME);
    
    KerberosRealmFieldDescriptor kerberosRealmFieldDescriptor = new KerberosRealmFieldDescriptor("Domain/Realm Name", "");
    
    kerberosRealmFieldDescriptor.addValidator(REQUIRED_VALIDATOR);
    gui.addField(kerberosRealmFieldDescriptor);
    

    Set<String> contract = new HashSet();
    contract.add("principal");
    contract.add("domain");
    contract.add("username");
    contract.add("sids");
    
    this.tokenProcessorDescriptor = new TokenProcessorDescriptor(TOKEN_PROCESSOR_NAME, this, gui, "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ", contract);
    this.tokenProcessorDescriptor.setSupportsExtendedContract(false);
  }
  
  public TokenProcessorDescriptor getPluginDescriptor()
  {
    return this.tokenProcessorDescriptor;
  }
  

  public TokenContext processToken(BinarySecurityToken token)
    throws InvalidTokenException, TokenProcessingException
  {
    KerberosRealmAccessor kerberosRealmAccessor = new KerberosRealmAccessor();
    
    KerberosRealm kerberosRealm = kerberosRealmAccessor.getKerberosRealm(this.kerberosRealmName);
    try
    {
      kerberosUtil = new KerberosUtil(kerberosRealm);
    }
    catch (KerberosException e) {
      KerberosUtil kerberosUtil;
      throw new ConfigurationException("An error occured logging in to KDC", e);
    }
    KerberosUtil kerberosUtil;
    String principal = null;
    Set<String> sids = null;
    
    try
    {
      principal = kerberosUtil.validateTicket(token.getDecodedData());
    }
    catch (KerberosException e)
    {
      throw new TokenProcessingException("Error processing Kerberos Token", e);
    }
    
    try
    {
      sids = kerberosUtil.extractSids(token.getDecodedData());
    }
    catch (KerberosException e) {
      log.warn("Couldn't extract SIDs from Kerberos token. " + e.getMessage());
    }
    

    TokenContext tokenContext = new TokenContext();
    
    Map<String, AttributeValue> attrs = new HashMap(2);
    attrs.put("principal", new AttributeValue(principal));
    

    String[] parts = principal.split("@");
    String username = parts[0];
    String domain = parts.length == 2 ? parts[1] : null;
    
    attrs.put("username", new AttributeValue(username));
    attrs.put("domain", new AttributeValue(domain));
    attrs.put("sids", new AttributeValue(sids));
    tokenContext.setSubjectAttributes(attrs);
    
    return tokenContext;
  }
  
  public void configure(Configuration configuration)
  {
    this.kerberosRealmName = configuration.getFieldValue("Domain/Realm Name");
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\org\sourceid\wstrust\processor\kerberos\KerberosTokenProcessor.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */