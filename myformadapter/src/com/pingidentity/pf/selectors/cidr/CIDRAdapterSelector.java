package com.pingidentity.pf.selectors.cidr;

import com.pingidentity.common.util.HostAddressUtils;
import com.pingidentity.sdk.AuthenticationSelector;
import com.pingidentity.sdk.AuthenticationSelectorContext;
import com.pingidentity.sdk.AuthenticationSelectorContext.ResultType;
import com.pingidentity.sdk.AuthenticationSelectorDescriptor;
import com.pingidentity.sdk.AuthenticationSourceKey;
import com.pingidentity.sdk.CIDRUtils;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.common.VersionUtil;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.TableDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.FieldValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;



public class CIDRAdapterSelector
  implements AuthenticationSelector
{
  private final Log log = LogFactory.getLog(CIDRAdapterSelector.class);
  private final AuthenticationSelectorDescriptor authnSelectorDescriptor;
  private List<CIDRUtils> networkCheckers = new ArrayList();
  
  private String attributeName;
  
  static final String YES = "Yes";
  
  static final String NO = "No";
  private static final String NETWORKS_TABLE_NAME = "Networks";
  private static final String NETWORK_FIELD_NAME = "Network Range (CIDR notation)";
  private static final String RESULT_ATTR_NAME = "Result Attribute Name";
  private static final String DESCRIPTION = "This authentication selector chooses an authentication source at runtime based on a match found in the specified HTTP Header.";
  
  public CIDRAdapterSelector()
  {
    GuiConfigDescriptor guiConfigDescriptor = new GuiConfigDescriptor();
    guiConfigDescriptor.setDescription("This authentication selector chooses an authentication source at runtime based on a match found in the specified HTTP Header.");
    

    FieldDescriptor networkCIDR = new TextFieldDescriptor("Network Range (CIDR notation)", "A valid network range in CIDR notation");
    networkCIDR.addValidator(new FieldValidator()
    {
      public void validate(Field field)
        throws ValidationException
      {
        try
        {
          new CIDRUtils(field.getValue());
        }
        catch (IllegalArgumentException|UnknownHostException ex)
        {
          throw new ValidationException("Invalid network range.  Please verify that the network range is defined using CIDR notation. For example, 192.168.0.1/24.");
        }
      }
    });
    TableDescriptor networks = new TableDescriptor("Networks", "A table of valid networks");
    networks.addRowField(networkCIDR);
    guiConfigDescriptor.addTable(networks);
    

    guiConfigDescriptor.addField(new TextFieldDescriptor("Result Attribute Name", "Indicates (when specified) the attribute name in which to store the authentication selector result value."));
    
    guiConfigDescriptor.addValidator(new ConfigurationValidator()
    {
      public void validate(Configuration configuration)
        throws ValidationException
      {
        Table table = configuration.getTable("Networks");
        List<Row> rows = table.getRows();
        if (rows.isEmpty())
        {
          throw new ValidationException("Please add at least one network to the 'Networks' table.");
        }
        List<String> errors = new ArrayList();
        Set<String> networks = new HashSet();
        for (Row row : rows)
        {
          String network = row.getFieldValue("Network Range (CIDR notation)");
          if (!networks.add(network))
          {
            errors.add("Duplicate network: " + network);
          }
        }
        
        if (!errors.isEmpty())
        {
          throw new ValidationException(errors);
        }
      }
    });
    Set<String> results = new HashSet();
    results.add("Yes");
    results.add("No");
    this.authnSelectorDescriptor = new AuthenticationSelectorDescriptor("CIDR Authentication Selector", this, guiConfigDescriptor, results, VersionUtil.getVersion());
    this.authnSelectorDescriptor.setSupportsExtendedResults(false);
  }
  

  public void configure(Configuration configuration)
  {
    Table networks = configuration.getTable("Networks");
    for (Row network : networks.getRows())
    {
      try
      {

        CIDRUtils cidrUtils = new CIDRUtils(network.getFieldValue("Network Range (CIDR notation)"));
        this.networkCheckers.add(cidrUtils);
      }
      catch (UnknownHostException localUnknownHostException) {}
    }
    


    this.attributeName = configuration.getFieldValue("Result Attribute Name");
  }
  

  public PluginDescriptor getPluginDescriptor()
  {
    return this.authnSelectorDescriptor;
  }
  

  public AuthenticationSelectorContext selectContext(HttpServletRequest req, HttpServletResponse res, Map<AuthenticationSourceKey, String> mappedAuthnSourcesNames, Map<String, Object> extraParameters, String resumePath)
  {
    String remoteAddr = req.getRemoteAddr();
    if (remoteAddr != null)
    {
      this.log.debug("Using client address " + remoteAddr);
    }
    
    return getContext(remoteAddr);
  }
  
  AuthenticationSelectorContext getContext(String remoteAddr)
  {
    AuthenticationSelectorContext context = new AuthenticationSelectorContext();
    context.setResultType(AuthenticationSelectorContext.ResultType.CONTEXT);
    context.setResult("No");
    
    for (CIDRUtils networkChecker : this.networkCheckers)
    {
      try
      {
        if (networkChecker.isInRange(HostAddressUtils.getIpAddress(remoteAddr)))
        {
          context.setResult("Yes");
          this.log.debug(remoteAddr + " is within range " + networkChecker);
          break;
        }
      }
      catch (UnknownHostException e)
      {
        this.log.info("Invalid address value: " + remoteAddr);
        this.log.debug(e);
      }
    }
    return context;
  }
  


  public void callback(HttpServletRequest req, HttpServletResponse res, Map authnIdentifiers, AuthenticationSourceKey authenticationSourceKey, AuthenticationSelectorContext authnSelectorContext)
  {
    if ((StringUtils.isNotBlank(this.attributeName)) && (!authnIdentifiers.containsKey(this.attributeName)))
    {
      boolean anyAttributeValues = false;
      for (Object value : authnIdentifiers.values())
      {
        anyAttributeValues |= value instanceof AttributeValue;
      }
      

      Object attr = anyAttributeValues ? new AttributeValue(authnSelectorContext.getResult()) : authnSelectorContext.getResult();
      authnIdentifiers.put(this.attributeName, attr);
      this.log.debug("Attribute '" + this.attributeName + "added with value '" + authnSelectorContext.getResult());
    }
  }
  
  void setNetworkCheckers(List<CIDRUtils> networkCheckers)
  {
    this.networkCheckers = networkCheckers;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\selectors\cidr\CIDRAdapterSelector.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */