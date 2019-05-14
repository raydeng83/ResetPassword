package com.pingidentity.selectors;

import com.pingidentity.access.ClusterAccessor;
import com.pingidentity.sdk.AuthenticationSelector;
import com.pingidentity.sdk.AuthenticationSelectorContext;
import com.pingidentity.sdk.AuthenticationSelectorContext.ResultType;
import com.pingidentity.sdk.AuthenticationSelectorDescriptor;
import com.pingidentity.sdk.AuthenticationSourceKey;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.sourceid.common.VersionUtil;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.domain.mgmt.impl.Mode;
import org.sourceid.saml20.domain.mgmt.impl.ModeSupport;











public class ClusterNodeAdapterSelector
  implements AuthenticationSelector
{
  private static final String DESCRIPTION = "This authentication selector provides a means of choosing authentication sources at runtime based on the cluster node on which it is executing.";
  private static final String SELECTOR_NAME = "Cluster Node Authentication Selector";
  private static final Logger log = LogManager.getLogger(ClusterNodeAdapterSelector.class);
  
  private final PluginDescriptor pluginDescriptor = new AuthenticationSelectorDescriptor("Cluster Node Authentication Selector", this, new GuiConfigDescriptor("This authentication selector provides a means of choosing authentication sources at runtime based on the cluster node on which it is executing."), null, 
  


    VersionUtil.getVersion());
  




  public void configure(Configuration configuration)
  {
    if (ModeSupport.getMode() == Mode.STANDALONE)
    {
      log.warn("The cluster node authentication selector should not be used in standalone mode.");
    }
  }
  




  public PluginDescriptor getPluginDescriptor()
  {
    return this.pluginDescriptor;
  }
  







  public void callback(HttpServletRequest req, HttpServletResponse resp, Map authnIdentifiers, AuthenticationSourceKey authnSourceKey, AuthenticationSelectorContext authnSelectorContext) {}
  






  public AuthenticationSelectorContext selectContext(HttpServletRequest req, HttpServletResponse resp, Map<AuthenticationSourceKey, String> mappedAuthnSourcesNames, Map<String, Object> extraParameters, String resumePath)
  {
    AuthenticationSelectorContext context = new AuthenticationSelectorContext();
    context.setResultType(AuthenticationSelectorContext.ResultType.CONTEXT);
    
    String nodeIndex = Integer.toString(ClusterAccessor.getNodeIndex());
    
    log.debug("Cluster selector result: " + nodeIndex);
    
    context.setResult(nodeIndex);
    
    return context;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\selectors\ClusterNodeAdapterSelector.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */