package com.pingidentity.provisioner.saas.scim11serviceprovider;

import com.pingidentity.pingcommons.crypto.IDGenerator;
import com.pingidentity.pingone.PingOneAdminService;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.service.ProvisioningTargetUrls;
import org.sourceid.saml20.service.SpConnectionFactory;







public class PingOneScim11ServiceProviderPlugin
  extends Scim11ServiceProviderPlugin
{
  private static final long serialVersionUID = 1L;
  private static final String PLUGIN_ID = "PingOneSCIM11";
  private static final String PLUGIN_DESCRIPTION = "PingOne SCIM 1.1 Service Provider";
  
  public String getId()
  {
    return "PingOneSCIM11";
  }
  

  public String getDescription()
  {
    return "PingOne SCIM 1.1 Service Provider";
  }
  

  public boolean isTestConnectionSupported()
  {
    if (!MgmtFactory.getPingOneAdminService().isAssociated())
    {
      return super.isTestConnectionSupported();
    }
    

    return false;
  }
  

  public boolean isUserSelectable()
  {
    return false;
  }
  

  protected List<FieldDescriptor> createDescriptors()
  {
    if (!MgmtFactory.getPingOneAdminService().isAssociated())
    {
      return super.createDescriptors();
    }
    
    SpConnectionFactory spConnFactory = MgmtFactory.getPingOneAdminService().getSpConnectionFactory();
    
    ProvisioningTargetUrls targetUrls = spConnFactory.getProvisioningTargetUrls();
    Map<String, String> fieldMap = new HashMap();
    fieldMap.put("usersUrl", targetUrls.getUsersUrl());
    fieldMap.put("groupsUrl", targetUrls.getGroupsUrl());
    
    fieldMap.put("authentication", "basic");
    fieldMap.put("basicAuthUser", "prov-" + IDGenerator.rndAlphaNumeric(10));
    fieldMap.put("basicAuthPass", IDGenerator.rndAlphaNumeric(25));
    
    fieldMap.put("deprovisionMethod", "deleteUser");
    fieldMap.put("isPatchSupported", "true");
    fieldMap.put("useDnAsGroupName", "true");
    
    List<FieldDescriptor> descriptors = super.createDescriptors();
    for (FieldDescriptor descriptor : descriptors)
    {
      if (fieldMap.containsKey(descriptor.getName()))
      {
        descriptor.setDefaultValue((String)fieldMap.get(descriptor.getName()));
      }
    }
    
    return descriptors;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\provisioner\saas\scim11serviceprovider\PingOneScim11ServiceProviderPlugin.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */