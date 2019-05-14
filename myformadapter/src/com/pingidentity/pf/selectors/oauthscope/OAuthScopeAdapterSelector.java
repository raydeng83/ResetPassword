package com.pingidentity.pf.selectors.oauthscope;

import com.pingidentity.sdk.AuthenticationSelector;
import com.pingidentity.sdk.AuthenticationSelectorContext;
import com.pingidentity.sdk.AuthenticationSelectorContext.ResultType;
import com.pingidentity.sdk.AuthenticationSelectorDescriptor;
import com.pingidentity.sdk.AuthenticationSourceKey;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.GuiConfigDescriptorBuilder;
import com.pingidentity.sdk.PluginDescriptor;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.common.VersionUtil;
import org.sourceid.oauth20.domain.ScopeManager;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;







public class OAuthScopeAdapterSelector
  implements AuthenticationSelector, GuiConfigDescriptorBuilder
{
  private static final Log LOG = LogFactory.getLog(OAuthScopeAdapterSelector.class);
  
  private static final String SELECTOR_NAME = "OAuth Scope Authentication Selector";
  
  private static final String DESCRIPTION = "This authentication selector provides a means of choosing authentication sources at runtime based on the OAuth scope request received by the Authorization Endpoint. Select all scopes required to trigger a \"Yes\" result from this selector. Create multiple instances to handle boolean 'OR' cases.";
  private static final String SCOPE_CLEANUP_DESCRIPTION = "This OAuth scope is no longer provided by the OAuth Authorization Server. Uncheck this scope and re-save this authentication selector or re-add it to the authorization server.";
  private static final String RESULT_YES = "Yes";
  private static final String RESULT_NO = "No";
  private static final String IN_SCOPE_DELIM = " ";
  private static final String GROUP_SUFFIX = " (Group)";
  
  private class OAuthScopeConfigValidator
    implements ConfigurationValidator
  {
    private final Map<String, String> availableScopes;
    private final Set<String> invalidScopes;
    
    public OAuthScopeConfigValidator(Set<String> availableScopes)
    {
      this.availableScopes = availableScopes;
      this.invalidScopes = invalidScopes;
    }
    

    public void validate(Configuration configuration)
      throws ValidationException
    {
      if (this.availableScopes.isEmpty())
      {
        throw new ValidationException("The OAuth Authorization Server doesn't have any scopes configured. Add at least one scope to the Authorization Server in order to use this authentication selector.");
      }
      


      boolean aScopeChecked = false;
      
      for (Iterator localIterator = this.availableScopes.entrySet().iterator(); localIterator.hasNext();) { entry = (Map.Entry)localIterator.next();
        
        String scope = (String)entry.getKey();
        checked = configuration.getBooleanFieldValue(scope);
        
        if (checked)
        {
          aScopeChecked = true;
          break;
        } }
      Map.Entry<String, String> entry;
      boolean checked;
      if (!aScopeChecked)
      {
        throw new ValidationException("Please choose at least one valid scope requirement.");
      }
      

      Object selectedInvalidScopes = new HashSet();
      
      for (String invalidScope : this.invalidScopes)
      {
        if (configuration.getBooleanFieldValue(invalidScope))
        {
          ((Set)selectedInvalidScopes).add(invalidScope);
        }
      }
      
      if (!((Set)selectedInvalidScopes).isEmpty())
      {
        StringBuilder stringBuilder = new StringBuilder("The OAuth Authorization Server doesn't support the following scopes: ");
        
        boolean firstScope = true;
        for (String selectedInvalidScope : (Set)selectedInvalidScopes)
        {
          if (!firstScope)
          {
            stringBuilder.append(", ");
          }
          else
          {
            firstScope = false;
          }
          stringBuilder.append(selectedInvalidScope);
          stringBuilder.append('\n');
        }
        
        stringBuilder.append(". Please unselect these fields before saving.");
        
        throw new ValidationException(stringBuilder.toString());
      }
    }
  }
  
  private Set<String> requiredScopes = new HashSet();
  private final Set<String> invalidConfiguredScopes = new HashSet();
  

  private final ScopeManager scopeManager = MgmtFactory.getScopeManager();
  





  public void configure(Configuration configuration)
  {
    if (LOG.isDebugEnabled())
    {
      LOG.debug("loading configuration");
    }
    
    Map<String, String> requiredScopeDescriptions = new HashMap();
    categorizeScopes(configuration, null, requiredScopeDescriptions, this.invalidConfiguredScopes);
    this.requiredScopes = requiredScopeDescriptions.keySet();
  }
  





  public PluginDescriptor getPluginDescriptor()
  {
    Set<String> results = new HashSet();
    results.add("Yes");
    results.add("No");
    


    AuthenticationSelectorDescriptor authnSelectorDescriptor = new AuthenticationSelectorDescriptor("OAuth Scope Authentication Selector", this, this, results, VersionUtil.getVersion());
    authnSelectorDescriptor.setSupportsExtendedContract(false);
    
    return authnSelectorDescriptor;
  }
  






  public void callback(HttpServletRequest req, HttpServletResponse resp, Map authnIdentifiers, AuthenticationSourceKey authenticationSourceKey, AuthenticationSelectorContext authnSelectorContext) {}
  






  public AuthenticationSelectorContext selectContext(HttpServletRequest req, HttpServletResponse resp, Map<AuthenticationSourceKey, String> mappedAuthnSourcesNames, Map<String, Object> extraParameters, String resumePath)
  {
    AuthenticationSelectorContext context = new AuthenticationSelectorContext();
    context.setResultType(AuthenticationSelectorContext.ResultType.CONTEXT);
    context.setResult("No");
    
    if (this.requiredScopes.isEmpty())
    {
      if (LOG.isDebugEnabled())
      {
        LOG.debug("This OAuth Scope authentication selector doesn't have any required scopes. Returning a false context.");
      }
      
      return context;
    }
    

    String reqScope = extraParameters.containsKey("com.pingidentity.sdk.AdapterSelector.scope") ? (String)extraParameters.get("com.pingidentity.sdk.AdapterSelector.scope") : null;
    
    if (LOG.isDebugEnabled())
    {
      LOG.debug("Requested scopes: " + reqScope);
      LOG.debug("Required scopes: " + this.requiredScopes.toString());
    }
    Set<String> inScopes;
    if (reqScope != null)
    {

      inScopes = new HashSet();
      for (String inScope : reqScope.split(" "))
      {
        if (!inScope.isEmpty())
        {
          inScopes.add(inScope);
        }
      }
      

      if (!inScopes.isEmpty())
      {
        context.setResult("Yes");
      }
      

      for (??? = this.requiredScopes.iterator(); ((Iterator)???).hasNext();) { String requiredScope = (String)((Iterator)???).next();
        
        boolean match = inScopes.contains(requiredScope);
        
        if (!match)
        {
          if (LOG.isDebugEnabled())
          {
            LOG.debug("Scope requirement not met: " + requiredScope);
          }
          
          context.setResult("No");
          break;
        }
      }
    }
    
    if (LOG.isDebugEnabled())
    {
      LOG.debug("Returning context: " + context.getResult());
    }
    
    return context;
  }
  

  public GuiConfigDescriptor buildNewGuiDescriptor()
  {
    return buildGuiDescriptor(getScopeDescriptions(), Collections.emptySet());
  }
  

  public GuiConfigDescriptor buildConfiguredGuiDescriptor(Configuration config)
  {
    Map<String, String> availSortedScopes = new HashMap();
    Set<String> invalidSortedScopes = new HashSet();
    
    categorizeScopes(config, availSortedScopes, null, invalidSortedScopes);
    
    return buildGuiDescriptor(availSortedScopes, invalidSortedScopes);
  }
  
  private GuiConfigDescriptor buildGuiDescriptor(Map<String, String> availableScopes, Set<String> invalidScopes)
  {
    GuiConfigDescriptor guiDescriptor = new GuiConfigDescriptor();
    guiDescriptor.setDescription("This authentication selector provides a means of choosing authentication sources at runtime based on the OAuth scope request received by the Authorization Endpoint. Select all scopes required to trigger a \"Yes\" result from this selector. Create multiple instances to handle boolean 'OR' cases.");
    

    Map<String, String> scopeFields = new TreeMap(String.CASE_INSENSITIVE_ORDER);
    scopeFields.putAll(availableScopes);
    
    for (String invalidScope : invalidScopes)
    {
      scopeFields.put(invalidScope, "This OAuth scope is no longer provided by the OAuth Authorization Server. Uncheck this scope and re-save this authentication selector or re-add it to the authorization server.");
    }
    

    for (Map.Entry<String, String> scopeEntry : scopeFields.entrySet())
    {
      CheckBoxFieldDescriptor scopeCheck = new CheckBoxFieldDescriptor((String)scopeEntry.getKey(), (String)scopeEntry.getValue());
      guiDescriptor.addField(scopeCheck);
    }
    

    OAuthScopeConfigValidator validator = new OAuthScopeConfigValidator(availableScopes, invalidScopes);
    guiDescriptor.addValidator(validator);
    
    return guiDescriptor;
  }
  






  private void categorizeScopes(Configuration configuration, Map<String, String> availableScopes, Map<String, String> requiredScopes, Set<String> invalidScopes)
  {
    if (availableScopes != null)
    {
      availableScopes.clear();
    }
    if (requiredScopes != null)
    {
      requiredScopes.clear();
    }
    invalidScopes.clear();
    

    for (Field field : configuration.getFields())
    {

      if (field.getValueAsBoolean())
      {
        invalidScopes.add(field.getName());
      }
    }
    

    for (Map.Entry<String, String> entry : getScopeDescriptions().entrySet())
    {
      String scope = (String)entry.getKey();
      
      Field scopeCheck = configuration.getField(scope);
      if (scopeCheck != null)
      {
        if ((requiredScopes != null) && (scopeCheck.getValueAsBoolean()))
        {
          requiredScopes.put(scope, entry.getValue());
        }
        
        invalidScopes.remove(scope);
      }
      
      if (availableScopes != null)
      {
        availableScopes.put(scope, entry.getValue());
      }
    }
  }
  
  private Map<String, String> getScopeDescriptions()
  {
    Map<String, String> scopeAndGroupDescriptions = new TreeMap(String.CASE_INSENSITIVE_ORDER);
    scopeAndGroupDescriptions.putAll(this.scopeManager.getScopeDescriptions());
    
    for (Map.Entry<String, String> entry : this.scopeManager.getScopeGroupDescriptions().entrySet())
    {
      scopeAndGroupDescriptions.put(entry.getKey(), (String)entry.getValue() + " (Group)");
    }
    
    scopeAndGroupDescriptions.putAll(this.scopeManager.getExclusiveScopeDescriptions());
    
    for (Map.Entry<String, String> entry : this.scopeManager.getExclusiveScopeGroupDescriptions().entrySet())
    {
      scopeAndGroupDescriptions.put(entry.getKey(), (String)entry.getValue() + " (Group)");
    }
    
    return scopeAndGroupDescriptions;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\selectors\oauthscope\OAuthScopeAdapterSelector.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */