package com.pingidentity.pf.selectors.saml;

import com.pingidentity.sdk.AuthenticationSelector;
import com.pingidentity.sdk.AuthenticationSelectorContext;
import com.pingidentity.sdk.AuthenticationSelectorContext.ResultType;
import com.pingidentity.sdk.AuthenticationSelectorDescriptor;
import com.pingidentity.sdk.AuthenticationSourceKey;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.common.VersionUtil;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.domain.AdvancedAuthnPolicy;
import org.sourceid.saml20.protocol.AssertionMapKeys;



public class SamlAuthnContextAdapterSelector
  implements AuthenticationSelector
{
  Log log = LogFactory.getLog(SamlAuthnContextAdapterSelector.class);
  AuthenticationSelectorDescriptor authnSelectorDescriptor;
  Set<String> authnContexts = new HashSet();
  boolean updateAttribute = false;
  
  private static String UPDATE_ATTR_CHECKBOX_NAME = "Add or Update AuthN Context Attribute";
  private static String DESCRIPTION = "This authentication selector selects an authentication source based on the authentication context requested by an SP, for SP-initiated SSO or through OpenID Connect.  SAML-specified contexts, or any ad-hoc context agreed upon between the IdP and SP partners, are specified on the Selector Result Values screen.";
  

  public SamlAuthnContextAdapterSelector()
  {
    GuiConfigDescriptor guiConfigDescriptor = new GuiConfigDescriptor();
    guiConfigDescriptor.setDescription(DESCRIPTION);
    Set<String> results = new HashSet();
    CheckBoxFieldDescriptor updateAuthnContextAttribute = new CheckBoxFieldDescriptor(UPDATE_ATTR_CHECKBOX_NAME, "Indicates (when specified) if the AuthN Context attribute value will be updated with the authentication selector result value.");
    

    updateAuthnContextAttribute.setDefaultValue(true);
    guiConfigDescriptor.addField(updateAuthnContextAttribute);
    

    this.authnSelectorDescriptor = new AuthenticationSelectorDescriptor("Requested AuthN Context Authentication Selector", this, guiConfigDescriptor, results, VersionUtil.getVersion());
    this.authnSelectorDescriptor.setSupportsExtendedResults(true);
  }
  

  public void configure(Configuration configuration)
  {
    this.authnContexts.clear();
    this.authnContexts.addAll(configuration.getAdditionalAttrNames());
    this.updateAttribute = configuration.getBooleanFieldValue(UPDATE_ATTR_CHECKBOX_NAME);
  }
  

  public PluginDescriptor getPluginDescriptor()
  {
    return this.authnSelectorDescriptor;
  }
  



  public AuthenticationSelectorContext selectContext(HttpServletRequest req, HttpServletResponse res, Map<AuthenticationSourceKey, String> mappedAuthnSourcesNames, Map<String, Object> extraParameters, String resumePath)
  {
    AuthenticationSelectorContext context = new AuthenticationSelectorContext();
    context.setResultType(AuthenticationSelectorContext.ResultType.CONTEXT);
    
    if ((extraParameters.get("com.pingidentity.adapter.extra.parameter.authnPolicy") != null) && 
      ((extraParameters.get("com.pingidentity.adapter.extra.parameter.authnPolicy") instanceof AuthnPolicy)))
    {
      AuthnPolicy authnPolicy = (AuthnPolicy)extraParameters.get("com.pingidentity.adapter.extra.parameter.authnPolicy");
      
      if ((authnPolicy instanceof AdvancedAuthnPolicy)) {
        for (String requestedContext : ((AdvancedAuthnPolicy)authnPolicy).getRequestedAuthnContextDecl())
        {
          if (this.authnContexts.contains(requestedContext))
          {
            context.setResult(requestedContext);
            break;
          }
        }
      }
      
      for (String requestedContext : authnPolicy.getRequestAuthnContexts())
      {
        if (this.authnContexts.contains(requestedContext))
        {
          context.setResult(requestedContext);
          break;
        }
      }
    }
    


    return context;
  }
  


  public void callback(HttpServletRequest req, HttpServletResponse res, Map authnIdentifiers, AuthenticationSourceKey authenticationSourceKey, AuthenticationSelectorContext authnSelectorContext)
  {
    if (this.updateAttribute)
    {
      boolean anyAttributeValues = false;
      for (Object value : authnIdentifiers.values())
      {
        anyAttributeValues |= value instanceof AttributeValue;
      }
      
      Object attr = anyAttributeValues ? new AttributeValue(authnSelectorContext.getResult()) : authnSelectorContext.getResult();
      authnIdentifiers.put(AssertionMapKeys.getAuthnCtxKey(), attr);
      this.log.debug("Attribute '" + AssertionMapKeys.getAuthnCtxKey() + "' added with value '" + authnSelectorContext
        .getResult());
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\selectors\saml\SamlAuthnContextAdapterSelector.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */