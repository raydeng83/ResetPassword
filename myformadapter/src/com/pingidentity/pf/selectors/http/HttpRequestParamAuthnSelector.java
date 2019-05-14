package com.pingidentity.pf.selectors.http;

import com.pingidentity.sdk.AuthenticationSelector;
import com.pingidentity.sdk.AuthenticationSelectorContext;
import com.pingidentity.sdk.AuthenticationSelectorContext.ResultType;
import com.pingidentity.sdk.AuthenticationSelectorDescriptor;
import com.pingidentity.sdk.AuthenticationSourceKey;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.common.ExpressionMatchHandler;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
































public class HttpRequestParamAuthnSelector
  implements AuthenticationSelector
{
  private static final String DESCRIPTION = "This authentication selector provides a means of choosing authentication sources at runtime based on HTTP request parameters.";
  public static final String FIELD_HTTP_REQUEST_PARAMETER_NAME = "HTTP Request Parameter Name";
  private static final String FIELD_ENABLE_CASESENSITIVE = "Case-Sensitive Matching";
  private static final String DESC_HTTP_REQUEST_PARAMETER_NAME = "The exact name of the HTTP request parameter.";
  private static final String DESC_ENABLE_CASESENSITIVE = "Allows HTTP request parameter value matching to be case-sensitive.";
  private static final boolean DEFAULT_VALUE_ENABLE_CASESENSITIVE = true;
  private static final String PLUGIN_TYPE_NAME = "HTTP Request Parameter Authentication Selector";
  private String requestParamName = null;
  
  private boolean enableCaseSensitiveMatch = true;
  
  private ExpressionMatchHandler expressionHandler = null;
  
  private static final Log log = LogFactory.getLog(HttpRequestParamAuthnSelector.class);
  


  public void configure(Configuration configuration)
  {
    this.requestParamName = configuration.getFieldValue("HTTP Request Parameter Name");
    
    Field caseSensitiveField = configuration.getField("Case-Sensitive Matching");
    if (caseSensitiveField != null)
    {
      this.enableCaseSensitiveMatch = caseSensitiveField.getValueAsBoolean();
    }
    
    Collection<String> attrs = new ArrayList();
    attrs.addAll(configuration.getAdditionalAttrNames());
    this.expressionHandler = new ExpressionMatchHandler(attrs, this.enableCaseSensitiveMatch);
  }
  


  public PluginDescriptor getPluginDescriptor()
  {
    GuiConfigDescriptor guiConfigDescriptor = new GuiConfigDescriptor();
    guiConfigDescriptor.setDescription("This authentication selector provides a means of choosing authentication sources at runtime based on HTTP request parameters.");
    
    TextFieldDescriptor requestParamNameField = new TextFieldDescriptor("HTTP Request Parameter Name", "The exact name of the HTTP request parameter.");
    
    requestParamNameField.addValidator(new RequiredFieldValidator());
    guiConfigDescriptor.addField(requestParamNameField);
    
    CheckBoxFieldDescriptor enableCaseSensitiveField = new CheckBoxFieldDescriptor("Case-Sensitive Matching", "Allows HTTP request parameter value matching to be case-sensitive.");
    enableCaseSensitiveField.setDefaultValue(true);
    enableCaseSensitiveField.setDefaultForLegacyConfig(Boolean.toString(true));
    
    guiConfigDescriptor.addField(enableCaseSensitiveField);
    
    AuthenticationSelectorDescriptor authSelectorDescriptor = new AuthenticationSelectorDescriptor("HTTP Request Parameter Authentication Selector", this, guiConfigDescriptor, null);
    
    authSelectorDescriptor.setSupportsExtendedResults(true);
    
    return authSelectorDescriptor;
  }
  




  public AuthenticationSelectorContext selectContext(HttpServletRequest req, HttpServletResponse resp, Map<AuthenticationSourceKey, String> mappedAuthnSourcesNames, Map<String, Object> extraParameters, String resumePath)
  {
    AuthenticationSelectorContext context = new AuthenticationSelectorContext();
    context.setResultType(AuthenticationSelectorContext.ResultType.CONTEXT);
    log.debug("Extracting HTTP Request parameter value.");
    String requestParamValue = req.getParameter(this.requestParamName);
    
    if (requestParamValue != null)
    {
      String matchedParam = this.expressionHandler.getBestMatchedExpression(requestParamValue);
      context.setResult(matchedParam);
    }
    
    return context;
  }
  
  public void callback(HttpServletRequest req, HttpServletResponse resp, Map authnIdentifiers, AuthenticationSourceKey authenticationSourceKey, AuthenticationSelectorContext authnSelectorContext) {}
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\selectors\http\HttpRequestParamAuthnSelector.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */