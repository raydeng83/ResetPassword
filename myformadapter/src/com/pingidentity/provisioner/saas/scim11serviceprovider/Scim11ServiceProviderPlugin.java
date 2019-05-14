package com.pingidentity.provisioner.saas.scim11serviceprovider;

import com.pingidentity.provisioner.domain.mgmt.ProvisionerConfig;
import com.pingidentity.provisioner.mapping.FieldInfo;
import com.pingidentity.provisioner.sdk.AbstractSaasPluginWithGroups;
import com.pingidentity.provisioner.sdk.SaasGroupData;
import com.pingidentity.provisioner.sdk.SaasPluginException;
import com.pingidentity.provisioner.sdk.SaasPluginFieldInfo;
import com.pingidentity.provisioner.sdk.SaasUserData;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.WebResource.Builder;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.api.client.filter.ClientFilter;
import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.Response.Status.Family;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.utils.URIBuilder;
import org.sourceid.common.Util;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.AbstractSelectionFieldDescriptor.OptionValue;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.RadioGroupFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.IntegerValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.URLValidator;
import org.sourceid.saml20.domain.CoreUserOutboundScimAttributeConstants;
import org.sourceid.saml20.domain.SpConnection;
import org.sourceid.saml20.domain.scim.model.Schema;
import org.sourceid.saml20.domain.scim.model.SchemaAttribute;
import org.sourceid.saml20.domain.scim.util.CustomAttributesUtil;
import scim.schemas.core.v1.Address;
import scim.schemas.core.v1.Group;
import scim.schemas.core.v1.MultiValuedAttribute;
import scim.schemas.core.v1.Name;
import scim.schemas.core.v1.Resource;
import scim.schemas.core.v1.User;
























public class Scim11ServiceProviderPlugin
  extends AbstractSaasPluginWithGroups
{
  private static final long serialVersionUID = 1L;
  private static final String PLUGIN_ID = "SCIM11";
  private static final String PLUGIN_DESCRIPTION = "SCIM 1.1 Service Provider";
  protected static final String FIELD_USERS_URL = "usersUrl";
  protected static final String FIELD_USERS_URL_DESC = "Users Resource URL";
  protected static final String FIELD_GROUPS_URL = "groupsUrl";
  protected static final String FIELD_GROUPS_URL_DESC = "Groups Resource URL";
  private static final String FIELD_ENT_USER_EXT = "enableEntExt";
  protected static final String FIELD_DEPROVISION_METHOD = "deprovisionMethod";
  protected static final String FIELD_DEPROVISION_METHOD_DESC = "Deprovision Method";
  protected static final String FIELD_DEPROVISION_OPT_DELETE_NAME = "Delete User";
  protected static final String FIELD_DEPROVISION_OPT_DELETE_VAL = "deleteUser";
  protected static final String FIELD_DEPROVISION_OPT_DISABLE_NAME = "Disable User";
  protected static final String FIELD_DEPROVISION_OPT_DISABLE_VAL = "disableUser";
  protected static final String FIELD_AUTH = "authentication";
  protected static final String FIELD_AUTH_DESC = "Authentication Method";
  protected static final String FIELD_AUTH_OPT_NONE_NAME = "None";
  protected static final String FIELD_AUTH_OPT_NONE_VAL = "none";
  protected static final String FIELD_AUTH_OPT_BASIC_NAME = "Basic Authentication";
  protected static final String FIELD_AUTH_OPT_BASIC_VAL = "basic";
  protected static final String FIELD_AUTH_OPT_OAUTH2_BEARER_TOKEN = "OAuth 2.0 Bearer Token";
  protected static final String FIELD_AUTH_OPT_OAUTH2_BEARER_TOKEN_VAL = "oauth_bearer_token";
  protected static final String FIELD_BASIC_AUTH_USER = "basicAuthUser";
  protected static final String FIELD_BASIC_AUTH_USER_DESC = "User";
  protected static final String FIELD_BASIC_AUTH_PASS = "basicAuthPass";
  protected static final String FIELD_BASIC_AUTH_PASS_DESC = "Password";
  protected static final String FIELD_PATCH_SUPPORTED = "isPatchSupported";
  protected static final String FIELD_PATCH_SUPPORTED_DESC = "SCIM SP supports PATCH updates";
  protected static final String FIELD_DN_AS_GROUP_NAME = "useDnAsGroupName";
  protected static final String FIELD_DN_AS_GROUP_NAME_DESC = "Provision groups with distinguished name";
  protected static final String FIELD_CLIENT_ID = "clientId";
  protected static final String FIELD_CLIENT_ID_DESC = "Client ID";
  protected static final String FIELD_CLIENT_SECRET = "clientSecret";
  protected static final String FIELD_CLIENT_SECRET_DESC = "Client Secret";
  protected static final String FIELD_TOKEN_ENDPOINT_URL = "tokenEndpoint";
  protected static final String FIELD_TOKEN_ENDPOINT_URL_DESC = "Token Endpoint URL";
  protected static final String FIELD_RATE_LIMIT_CODE = "rateLimitErrorCode";
  protected static final String FIELD_RATE_LIMIT_CODE_DESC = "Rate Limit Error Code";
  protected static final String FIELD_RATE_LIMIT_CODE_DEFAULT = "429";
  private static final String PROPS_CORE_USER = "com/pingidentity/provisioner/saas/scim11serviceprovider/scim11-user-fields.properties";
  private static final String PROPS_ENT_USER = "com/pingidentity/provisioner/saas/scim11serviceprovider/scim11-enterpriseuser-fields.properties";
  private static final String DEFAULT_MAPPINGS = "com/pingidentity/provisioner/saas/scim11serviceprovider/mappings.default.properties";
  private static final String MASKED_VALUE = "*****";
  private static final String SCIM_VERSION = "urn:scim:schemas:core:1.0";
  private final Log log = LogFactory.getLog(getClass());
  
  private volatile List<FieldDescriptor> descriptors;
  private final List<SaasPluginFieldInfo> coreUserFieldInfo;
  private final List<SaasPluginFieldInfo> entUserFieldInfo;
  private Client restClient;
  private ClientFilter clientAuthFilter;
  private String usersUrl;
  private String groupsUrl;
  private boolean isEntUser;
  private String authMethod;
  private String basicAuthUser;
  private String basicAuthPass;
  private boolean isPatchSupported;
  private boolean usingDnAsGroupName;
  private String deprovisionMethod = "disableUser";
  private String clientId;
  private String clientSecret;
  private String tokenEndpoint;
  private Integer rateLimitErrorCode = Integer.valueOf("429");
  
  public Scim11ServiceProviderPlugin()
  {
    setSaasUsernameFieldCode(CoreUserOutboundScimAttributeConstants.USER_FIELD_USERNAME.getId());
    
    try
    {
      List<FieldInfo> coreUserFields = FieldInfo.parseFieldsInfo("com/pingidentity/provisioner/saas/scim11serviceprovider/scim11-user-fields.properties");
      List<FieldInfo> entUserField = FieldInfo.parseFieldsInfo("com/pingidentity/provisioner/saas/scim11serviceprovider/scim11-enterpriseuser-fields.properties");
      
      this.coreUserFieldInfo = Collections.unmodifiableList(convertFieldInfoToSaasPluginFieldInfo(coreUserFields));
      this.entUserFieldInfo = Collections.unmodifiableList(convertFieldInfoToSaasPluginFieldInfo(entUserField));
    }
    catch (IOException e)
    {
      throw new RuntimeException("Unable to load user fields!");
    }
  }
  

  public String getDescription()
  {
    return "SCIM 1.1 Service Provider";
  }
  

  public String getId()
  {
    return "SCIM11";
  }
  
  protected Properties loadDefaultMappings()
    throws IOException
  {
    Properties defaultMappings = new Properties();
    
    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    defaultMappings.load(classLoader.getResourceAsStream("com/pingidentity/provisioner/saas/scim11serviceprovider/mappings.default.properties"));
    
    return defaultMappings;
  }
  
  public void checkSaasConnection()
    throws SaasPluginException
  {
    boolean groupConfigured = StringUtils.isNotEmpty(this.groupsUrl);
    
    if ((StringUtils.isNotEmpty(this.usersUrl)) && (groupConfigured))
    {
      try
      {
        URL tempUserUrl = new URL(this.usersUrl);
        URL tempGroupUrl = new URL(this.groupsUrl);
        
        if (!tempUserUrl.getHost().equalsIgnoreCase(tempGroupUrl.getHost()))
        {
          throw new SaasPluginException("Users and Groups Connection URL must have the same host name");
        }
      }
      catch (MalformedURLException e)
      {
        throw new SaasPluginException(e);
      }
    }
    
    checkUserConnection();
    
    if (groupConfigured)
    {
      checkGroupConnection();
    }
  }
  
  private void checkUserConnection() throws SaasPluginException
  {
    if (this.log.isInfoEnabled())
    {
      this.log.info("Testing SCIM connection to " + this.usersUrl);
    }
    
    try
    {
      if (!checkConnection(this.usersUrl))
      {
        throw new SaasPluginException("SCIM users connection failed");
      }
      
    }
    catch (Exception e)
    {
      throw new SaasPluginException("SCIM users connection failed", e);
    }
  }
  
  private void checkGroupConnection() throws SaasPluginException
  {
    if (this.log.isInfoEnabled())
    {
      this.log.info("Testing SCIM connection to " + this.groupsUrl);
    }
    
    try
    {
      if (!checkConnection(this.groupsUrl))
      {
        throw new SaasPluginException("SCIM groups connection failed");
      }
      
    }
    catch (Exception e)
    {
      throw new SaasPluginException("SCIM groups connection failed", e);
    }
  }
  

  private boolean checkConnection(String baseUrl)
  {
    String fakeResourceId = "11111111-1111-1111-1111-111111111111";
    


    boolean retry = false;
    int retryCount = 0;
    ClientResponse response;
    Response.Status httpStatus;
    do
    {
      try {
        resource = this.restClient.resource(getResourceUrl(baseUrl, fakeResourceId));
      }
      catch (SaasPluginException e) {
        WebResource resource;
        this.log.debug("Check connection failed. " + e.getMessage());
        return false;
      }
      
      WebResource resource;
      
      response = (ClientResponse)resource.accept(new String[] { "application/json" }).get(ClientResponse.class);
      
      httpStatus = Response.Status.fromStatusCode(response.getStatus());
      
      if (("oauth_bearer_token".equals(this.authMethod)) && (httpStatus == Response.Status.UNAUTHORIZED))
      {


        this.log.debug("Access has token expired.  Getting a new token and retrying...");
        
        retry = true;
        ((OAuth2BearerTokenAuthFilter)this.clientAuthFilter).resetAccessToken();
      }
      
      retryCount++;
    }
    while ((retry) && (retryCount <= 1));
    
    if (httpStatus == Response.Status.NOT_FOUND)
    {
      this.log.info("SCIM connection successful");
      return true;
    }
    if (httpStatus == Response.Status.OK)
    {

      response.getEntity(User.class);
      this.log.info("SCIM connection successful");
      return true;
    }
    
    return false;
  }
  
  public void closeSaasConnection()
    throws SaasPluginException
  {
    if (this.restClient != null)
    {
      this.restClient.destroy();
      this.restClient = null;
    }
  }
  
  public String createUser(SaasUserData saasUserData)
    throws SaasPluginException
  {
    UserWithCustomAttributes user = createUserPojo(saasUserData);
    
    if (this.log.isInfoEnabled())
    {
      this.log.info("Attempting to create SCIM 1.1 User...");
    }
    
    boolean maskUsername = saasUserData.getMaskedFields().contains(CoreUserOutboundScimAttributeConstants.USER_FIELD_USERNAME.getId());
    User createdUser = provisionUser(user, this.usersUrl, false, maskUsername);
    
    if (this.log.isInfoEnabled())
    {
      String maskedName = getMaskedUsername(user.getUserName(), maskUsername);
      this.log.info("User '" + maskedName + "' was successfully created on the SCIM Service Provider");
    }
    
    return createdUser != null ? createdUser.getId() : null;
  }
  

  public List<FieldDescriptor> getConnectionParameterDescriptors()
  {
    if (this.descriptors != null)
    {
      return this.descriptors;
    }
    this.descriptors = Collections.unmodifiableList(createDescriptors());
    return this.descriptors;
  }
  
  public List<SaasPluginFieldInfo> getFieldInfo()
    throws SaasPluginException
  {
    List<SaasPluginFieldInfo> fieldInfos = new LinkedList();
    fieldInfos.addAll(this.coreUserFieldInfo);
    if (this.isEntUser)
    {
      fieldInfos.addAll(this.entUserFieldInfo);
    }
    
    return fieldInfos;
  }
  

  public String getSaasUserIdFieldName()
  {
    return CoreUserOutboundScimAttributeConstants.USER_FIELD_USERNAME.getId();
  }
  

  public SaasUserData getUser(String saasUserGuid, String saasUsername)
    throws SaasPluginException
  {
    if (saasUserGuid == null)
    {
      return null;
    }
    
    if (this.log.isInfoEnabled())
    {
      this.log.info("Attempting to retrieve user '" + saasUserGuid + "'");
    }
    
    WebResource userResource = this.restClient.resource(getResourceUrl(this.usersUrl, saasUserGuid));
    


    ClientResponse response = (ClientResponse)userResource.accept(new String[] { "application/json" }).get(ClientResponse.class);
    
    Response.Status httpStatus = Response.Status.fromStatusCode(response.getStatus());
    

    if (httpStatus == Response.Status.NOT_FOUND)
    {
      return null;
    }
    

    if (httpStatus.getFamily() != Response.Status.Family.SUCCESSFUL)
    {
      String errorMessage = "Unable to retrieve existing user '" + saasUserGuid + "' from service provider. Server returned status '" + response.getStatus() + "'";
      if (this.log.isErrorEnabled())
      {
        this.log.error(errorMessage + " with response: " + (String)response.getEntity(String.class));
      }
      
      throw new SaasPluginException(errorMessage);
    }
    
    logDebugResponse(response);
    
    if (this.log.isInfoEnabled())
    {
      this.log.info("Successfully retrieved user '" + saasUserGuid + "'");
    }
    
    User returnedUser = (User)response.getEntity(User.class);
    
    SaasUserData userData = new SaasUserData(saasUserGuid);
    Map<String, List<String>> attrMap = userData.getAttributeMap();
    addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_USERNAME.getId(), returnedUser.getUserName());
    
    if (returnedUser.getActive() != null)
    {
      userData.setAccountEnabled(returnedUser.getActive().booleanValue());
    }
    
    Name name = returnedUser.getName();
    if (name != null)
    {
      addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_FORMATTED_NAME.getId(), name.getFormatted());
      addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_FAMILY_NAME.getId(), name.getFamilyName());
      addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_GIVEN_NAME.getId(), name.getGivenName());
      addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_MIDDLE_NAME.getId(), name.getMiddleName());
      addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_PREFIX.getId(), name.getHonorificPrefix());
      addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_SUFFIX.getId(), name.getHonorificSuffix());
    }
    
    addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_DISPLAY_NAME.getId(), returnedUser.getDisplayName());
    addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_NICKNAME.getId(), returnedUser.getNickName());
    addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_PROFILE_URL.getId(), returnedUser.getProfileUrl());
    addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_TITLE.getId(), returnedUser.getTitle());
    addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_USER_TYPE.getId(), returnedUser.getUserType());
    addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_PREF_LANG.getId(), returnedUser.getPreferredLanguage());
    addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_LOCALE.getId(), returnedUser.getLocale());
    addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_TIMEZONE.getId(), returnedUser.getTimezone());
    addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_PASSWORD.getId(), returnedUser.getPassword());
    


    addMVAttrToAttrMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_EMAIL.getId(), CoreUserOutboundScimAttributeConstants.USER_FIELD_EMAIL_TYPE.getId(), returnedUser.getEmails());
    addMVAttrToAttrMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_PHONE_NUM.getId(), CoreUserOutboundScimAttributeConstants.USER_FIELD_PHONE_NUM_TYPE.getId(), returnedUser.getPhoneNumbers());
    addMVAttrToAttrMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_IMS.getId(), CoreUserOutboundScimAttributeConstants.USER_FIELD_IMS_TYPE.getId(), returnedUser.getIms());
    addMVAttrToAttrMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_PHOTO.getId(), CoreUserOutboundScimAttributeConstants.USER_FIELD_PHOTO_TYPE.getId(), returnedUser.getPhotos());
    
    List<Address> addresses = returnedUser.getAddresses();
    if ((addresses != null) && (!addresses.isEmpty()))
    {
      Address address = getPrimaryAddress(addresses);
      
      addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_FORMATTED_ADDR.getId(), address.getFormatted());
      addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_STREET_ADDR.getId(), address.getStreetAddress());
      addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_LOCALITY.getId(), address.getLocality());
      addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_REGION.getId(), address.getRegion());
      addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_POSTAL_CODE.getId(), address.getPostalCode());
      addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_COUNTRY.getId(), address.getCountry());
      addValueToAttributeMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_ADDR_TYPE.getId(), address.getType());
    }
    
    addMVAttrToAttrMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_ENTITLEMENTS.getId(), returnedUser.getEntitlements());
    addMVAttrToAttrMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_ROLES.getId(), returnedUser.getRoles());
    addMVAttrToAttrMap(attrMap, CoreUserOutboundScimAttributeConstants.USER_FIELD_CERTS.getId(), returnedUser.getEntitlements());
    



















    return userData;
  }
  
  public void initSaasConnection(List<Field> fields)
    throws SaasPluginException
  {
    for (Field f : fields)
    {
      String fieldName = f.getName();
      if ("authentication".equals(fieldName))
      {
        this.authMethod = f.getValue();
      }
      else if ("basicAuthPass".equals(fieldName))
      {
        this.basicAuthPass = f.getValue();
      }
      else if ("basicAuthUser".equals(fieldName))
      {
        this.basicAuthUser = f.getValue();
      }
      else if ("clientId".equals(fieldName))
      {
        this.clientId = f.getValue();
      }
      else if ("clientSecret".equals(fieldName))
      {
        this.clientSecret = f.getValue();
      }
      else if ("tokenEndpoint".equals(fieldName))
      {
        this.tokenEndpoint = f.getValue();
      }
      else if ("enableEntExt".equals(fieldName))
      {
        this.isEntUser = f.getValueAsBoolean();
      }
      else if ("groupsUrl".equals(fieldName))
      {
        this.groupsUrl = StringUtils.strip(f.getValue());
      }
      else if ("usersUrl".equals(fieldName))
      {
        this.usersUrl = StringUtils.strip(f.getValue());
      }
      else if ("isPatchSupported".equals(fieldName))
      {
        this.isPatchSupported = f.getValueAsBoolean();
      }
      else if ("useDnAsGroupName".equals(fieldName))
      {
        this.usingDnAsGroupName = f.getValueAsBoolean();
      }
      else if ("deprovisionMethod".equals(fieldName))
      {
        String val = f.getValue();
        if (val != null)
        {
          this.deprovisionMethod = val;
        }
      }
      else if ("rateLimitErrorCode".equals(fieldName))
      {
        String fieldLimitStr = f.getValue();
        if (StringUtils.isNotBlank(fieldLimitStr))
        {
          this.rateLimitErrorCode = Integer.valueOf(Integer.parseInt(fieldLimitStr));
        }
      }
    }
    

    if (this.restClient == null)
    {
      Object clientConfig = new DefaultClientConfig(new Class[] { Scim11ContextProvider.class });
      this.restClient = Client.create((ClientConfig)clientConfig);
      

      if ("basic".equals(this.authMethod))
      {
        if ((StringUtils.isBlank(this.basicAuthPass)) || (StringUtils.isBlank(this.basicAuthUser)))
        {
          throw new SaasPluginException("Expected user and password for basic authentication method.");
        }
        this.clientAuthFilter = new HTTPBasicAuthFilter(this.basicAuthUser, this.basicAuthPass);
      }
      else if ("oauth_bearer_token".equals(this.authMethod))
      {
        this.clientAuthFilter = new OAuth2BearerTokenAuthFilter(this.tokenEndpoint, this.clientId, this.clientSecret, this.basicAuthUser, this.basicAuthPass);
      }
      
      if (this.clientAuthFilter != null)
      {
        this.restClient.addFilter(this.clientAuthFilter);
      }
    }
    


    checkSaasConnection();
  }
  
  public String updateUser(SaasUserData existingSaasUserData, SaasUserData updatedSaasUserData)
    throws SaasPluginException
  {
    UserWithCustomAttributes updatedUser = createUserPojo(updatedSaasUserData);
    
    if (this.log.isInfoEnabled())
    {
      this.log.info("Attempting to update SCIM 1.1 User...");
    }
    
    provisionUser(updatedUser, 
    
      getResourceUrl(this.usersUrl, updatedSaasUserData.getSaasUserGuid()), true, existingSaasUserData
      
      .getMaskedFields().contains(CoreUserOutboundScimAttributeConstants.USER_FIELD_USERNAME.getId()));
    
    if (this.log.isInfoEnabled())
    {
      String maskedName = getMaskedUsername(updatedUser.getUserName(), existingSaasUserData.getMaskedFields().contains(CoreUserOutboundScimAttributeConstants.USER_FIELD_USERNAME.getId()));
      this.log.info("User '" + maskedName + "' was successfully updated on the SCIM Service Provider");
    }
    
    return updatedUser.getId();
  }
  
  protected List<FieldDescriptor> createDescriptors()
  {
    List<FieldDescriptor> tempDescriptors = new ArrayList(6);
    
    TextFieldDescriptor userUrlDescriptor = new TextFieldDescriptor("usersUrl", "Users Resource URL");
    userUrlDescriptor.addValidator(new RequiredFieldValidator());
    userUrlDescriptor.addValidator(new URLValidator(), true);
    



    TextFieldDescriptor groupUrlDescriptor = new TextFieldDescriptor("groupsUrl", "Groups Resource URL");
    groupUrlDescriptor.addValidator(new URLValidator(), true);
    
    ArrayList<AbstractSelectionFieldDescriptor.OptionValue> optValues = new ArrayList(3);
    optValues.add(new AbstractSelectionFieldDescriptor.OptionValue("None", "none"));
    optValues.add(new AbstractSelectionFieldDescriptor.OptionValue("Basic Authentication", "basic"));
    optValues.add(new AbstractSelectionFieldDescriptor.OptionValue("OAuth 2.0 Bearer Token", "oauth_bearer_token"));
    
    RadioGroupFieldDescriptor authMethodDescriptor = new RadioGroupFieldDescriptor("authentication", "Authentication Method", optValues);
    authMethodDescriptor.setDefaultValue("basic");
    
    TextFieldDescriptor userDescriptor = new TextFieldDescriptor("basicAuthUser", "User");
    TextFieldDescriptor passwordDescriptor = new TextFieldDescriptor("basicAuthPass", "Password", true);
    TextFieldDescriptor clientIdDescriptor = new TextFieldDescriptor("clientId", "Client ID");
    TextFieldDescriptor clientSecretDescriptor = new TextFieldDescriptor("clientSecret", "Client Secret", true);
    
    TextFieldDescriptor tokenEndpointUrlDescriptor = new TextFieldDescriptor("tokenEndpoint", "Token Endpoint URL");
    tokenEndpointUrlDescriptor.addValidator(new URLValidator(), true);
    
    CheckBoxFieldDescriptor patchDescriptor = new CheckBoxFieldDescriptor("isPatchSupported", "SCIM SP supports PATCH updates");
    patchDescriptor.setDefaultValue(true);
    CheckBoxFieldDescriptor dnAsGroupNameDescriptor = new CheckBoxFieldDescriptor("useDnAsGroupName", "Provision groups with distinguished name");
    dnAsGroupNameDescriptor.setDefaultValue(true);
    
    ArrayList<AbstractSelectionFieldDescriptor.OptionValue> deprovisionOptions = new ArrayList(3);
    deprovisionOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("Delete User", "deleteUser"));
    deprovisionOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("Disable User", "disableUser"));
    RadioGroupFieldDescriptor deprovisionDescriptor = new RadioGroupFieldDescriptor("deprovisionMethod", "Deprovision Method", deprovisionOptions);
    deprovisionDescriptor.setDefaultValue("disableUser");
    
    TextFieldDescriptor rateLimitingDescriptor = new TextFieldDescriptor("rateLimitErrorCode", "Rate Limit Error Code");
    rateLimitingDescriptor.addValidator(new IntegerValidator(1, 999), true);
    rateLimitingDescriptor.setDefaultValue("429");
    
    tempDescriptors.add(userUrlDescriptor);
    tempDescriptors.add(groupUrlDescriptor);
    
    tempDescriptors.add(authMethodDescriptor);
    tempDescriptors.add(userDescriptor);
    tempDescriptors.add(passwordDescriptor);
    tempDescriptors.add(clientIdDescriptor);
    tempDescriptors.add(clientSecretDescriptor);
    tempDescriptors.add(tokenEndpointUrlDescriptor);
    tempDescriptors.add(patchDescriptor);
    tempDescriptors.add(dnAsGroupNameDescriptor);
    tempDescriptors.add(deprovisionDescriptor);
    tempDescriptors.add(rateLimitingDescriptor);
    
    return tempDescriptors;
  }
  
  private String getMaskedUsername(String username, boolean isMasked)
  {
    String maskedName = username;
    if (isMasked)
    {
      maskedName = "*****";
    }
    
    return maskedName;
  }
  
  public String deprovisionUser(SaasUserData existingSaasUserData, SaasUserData updatedSaasUserData)
    throws SaasPluginException
  {
    if ("deleteUser".equals(this.deprovisionMethod))
    {
      deleteUser(updatedSaasUserData.getSaasUserGuid());
      return updatedSaasUserData.getSaasUserGuid();
    }
    

    return updateUser(existingSaasUserData, updatedSaasUserData);
  }
  
  private void deleteUser(String guid)
    throws SaasPluginException
  {
    if (this.log.isInfoEnabled())
    {
      this.log.info("Attempting to delete resource '" + guid + "'");
    }
    
    String resourceUrl = getResourceUrl(this.usersUrl, guid);
    
    WebResource webResource = this.restClient.resource(resourceUrl);
    
    WebResource.Builder requestBuilder = webResource.accept(new String[] { "application/json" });
    
    ClientResponse response = (ClientResponse)requestBuilder.delete(ClientResponse.class);
    

    if (Response.Status.fromStatusCode(response.getStatus()).getFamily() != Response.Status.Family.SUCCESSFUL)
    {
      String errorMessage = "Unable to delete user '" + guid + "'. Server returned status '" + response.getStatus() + "'";
      if (this.log.isErrorEnabled())
      {
        this.log.error(errorMessage + " with response: " + (String)response.getEntity(String.class));
      }
      
      throw new SaasPluginException(errorMessage);
    }
    
    logDebugResponse(response);
    
    if (this.log.isInfoEnabled())
    {
      this.log.info("Successfully deleted resource '" + guid + "'");
    }
  }
  



  private void addValueToAttributeMap(Map<String, List<String>> attrMap, String attrName, String val)
  {
    if (val == null)
    {
      return;
    }
    
    ArrayList<String> list = new ArrayList(1);
    list.add(val);
    attrMap.put(attrName, list);
  }
  



  private void addMVAttrToAttrMap(Map<String, List<String>> attrMap, String attrValName, String attrTypeName, List<MultiValuedAttribute> vals)
  {
    if ((vals == null) || (vals.isEmpty()))
    {
      return;
    }
    

    MultiValuedAttribute mva = getPrimary(vals);
    Object val = mva.getValue();
    if ((val == null) || (!(val instanceof String)))
    {
      return;
    }
    String strVal = (String)val;
    String type = mva.getType();
    
    ArrayList<String> valList = new ArrayList(1);
    valList.add(strVal);
    attrMap.put(attrValName, valList);
    
    if ((type != null) && (attrTypeName != null))
    {
      ArrayList<String> typeList = new ArrayList(1);
      typeList.add(type);
      attrMap.put(attrTypeName, typeList);
    }
  }
  
  private void addMVAttrToAttrMap(Map<String, List<String>> attrMap, String attrValName, List<MultiValuedAttribute> vals)
  {
    addMVAttrToAttrMap(attrMap, attrValName, null, vals);
  }
  



  private List<SaasPluginFieldInfo> convertFieldInfoToSaasPluginFieldInfo(List<FieldInfo> fieldInfos)
  {
    List<SaasPluginFieldInfo> saasPluginFieldInfos = new LinkedList();
    for (FieldInfo fi : fieldInfos)
    {
      SaasPluginFieldInfo saasPluginFieldInfo = new SaasPluginFieldInfo(fi.getCode(), fi.getLabel());
      saasPluginFieldInfo.setDefault(fi.getDefault());
      saasPluginFieldInfo.setMaxLength(fi.getMaxLength());
      saasPluginFieldInfo.setMinLength(fi.getMinLength());
      saasPluginFieldInfo.setMultiValue(fi.isMultiValue());
      saasPluginFieldInfo.setNotes(fi.getNotes());
      saasPluginFieldInfo.setOptions(fi.getOptions());
      saasPluginFieldInfo.setRegEx(fi.getRegEx());
      saasPluginFieldInfo.setRequired(fi.isRequired());
      saasPluginFieldInfo.setUnique(fi.isUnique());
      saasPluginFieldInfo.setLdapMap(fi.isLdapMap());
      saasPluginFieldInfo.setPersistForMembership(fi.isPersistForMembership());
      
      saasPluginFieldInfos.add(saasPluginFieldInfo);
    }
    
    return saasPluginFieldInfos;
  }
  




  private List<MultiValuedAttribute> createSimpleMVAttributes(List<String> sourceVals)
  {
    if (sourceVals == null)
    {
      return null;
    }
    
    List<MultiValuedAttribute> attrs = new ArrayList();
    for (String sourceVal : sourceVals)
    {
      if (sourceVal != null)
      {
        MultiValuedAttribute entitlementAttr = new MultiValuedAttribute();
        entitlementAttr.setValue(sourceVal);
        attrs.add(entitlementAttr);
      }
    }
    
    return attrs;
  }
  




  private List<MultiValuedAttribute> createValueTypeMVAttribute(SaasUserData saasUserData, String valName, String typeName)
  {
    List<MultiValuedAttribute> list = new ArrayList();
    String value = saasUserData.getAttributeFirstValue(valName);
    String type = saasUserData.getAttributeFirstValue(typeName);
    if (value == null)
    {
      return null;
    }
    MultiValuedAttribute attr = new MultiValuedAttribute();
    attr.setValue(value);
    attr.setType(type);
    list.add(attr);
    return list;
  }
  
  private Group createGroupPojo(SaasGroupData saasGroupData)
  {
    Group group = new Group();
    group.setId(saasGroupData.getGuid());
    group.setDisplayName(saasGroupData.getName());
    group.setExternalId(saasGroupData.getInternalGuid());
    List<MultiValuedAttribute> memberAttrs = new ArrayList();
    
    if (saasGroupData.getMembersIterator() != null)
    {
      Iterator<SaasUserData> usersIterator = saasGroupData.getMembersIterator();
      
      while (usersIterator.hasNext())
      {
        SaasUserData user = (SaasUserData)usersIterator.next();
        
        if ((user != null) && (user.getSaasUserGuid() != null))
        {
          MultiValuedAttribute memberAttr = new MultiValuedAttribute();
          memberAttr.setValue(user.getSaasUserGuid());
          memberAttrs.add(memberAttr);
        }
      }
    }
    
    if (saasGroupData.getSubGroupMembersIterator() != null)
    {
      Iterator<SaasGroupData> subGroupsIterator = saasGroupData.getSubGroupMembersIterator();
      
      while (subGroupsIterator.hasNext())
      {
        SaasGroupData saasSubGroupData = (SaasGroupData)subGroupsIterator.next();
        
        if ((saasSubGroupData != null) && (saasSubGroupData.getGuid() != null))
        {
          MultiValuedAttribute memberAttr = new MultiValuedAttribute();
          memberAttr.setValue(saasSubGroupData.getGuid());
          memberAttrs.add(memberAttr);
        }
      }
    }
    
    if (!memberAttrs.isEmpty())
    {
      group.setMembers(memberAttrs);
    }
    
    List<String> schemas = new ArrayList();
    schemas.add("urn:scim:schemas:core:1.0");
    group.setSchemas(schemas);
    
    return group;
  }
  
  private UserWithCustomAttributes createUserPojo(SaasUserData saasUserData)
  {
    UserWithCustomAttributes user = new UserWithCustomAttributes();
    user.setId(saasUserData.getSaasUserGuid());
    user.setExternalId(saasUserData.getInternalGuid());
    user.setUserName(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_USERNAME.getId()));
    
    Name name = new Name();
    name.setFormatted(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_FORMATTED_NAME.getId()));
    name.setFamilyName(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_FAMILY_NAME.getId()));
    name.setGivenName(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_GIVEN_NAME.getId()));
    name.setMiddleName(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_MIDDLE_NAME.getId()));
    name.setHonorificPrefix(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_PREFIX.getId()));
    name.setHonorificSuffix(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_SUFFIX.getId()));
    
    user.setName(name);
    user.setDisplayName(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_DISPLAY_NAME.getId()));
    user.setNickName(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_NICKNAME.getId()));
    user.setProfileUrl(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_PROFILE_URL.getId()));
    user.setTitle(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_TITLE.getId()));
    user.setUserType(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_USER_TYPE.getId()));
    user.setPreferredLanguage(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_PREF_LANG.getId()));
    user.setLocale(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_LOCALE.getId()));
    user.setTimezone(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_TIMEZONE.getId()));
    user.setActive(Boolean.valueOf(saasUserData.isAccountEnabled()));
    user.setPassword(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_PASSWORD.getId()));
    


    user.setEmails(createValueTypeMVAttribute(saasUserData, CoreUserOutboundScimAttributeConstants.USER_FIELD_EMAIL
    
      .getId(), CoreUserOutboundScimAttributeConstants.USER_FIELD_EMAIL_TYPE
      .getId()));
    user.setPhoneNumbers(createValueTypeMVAttribute(saasUserData, CoreUserOutboundScimAttributeConstants.USER_FIELD_PHONE_NUM
    
      .getId(), CoreUserOutboundScimAttributeConstants.USER_FIELD_PHONE_NUM_TYPE
      .getId()));
    user.setIms(createValueTypeMVAttribute(saasUserData, CoreUserOutboundScimAttributeConstants.USER_FIELD_IMS
    
      .getId(), CoreUserOutboundScimAttributeConstants.USER_FIELD_IMS_TYPE
      .getId()));
    user.setPhotos(createValueTypeMVAttribute(saasUserData, CoreUserOutboundScimAttributeConstants.USER_FIELD_PHOTO
    
      .getId(), CoreUserOutboundScimAttributeConstants.USER_FIELD_PHOTO_TYPE
      .getId()));
    
    List<Address> addresses = new ArrayList();
    Address address = new Address();
    address.setFormatted(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_FORMATTED_ADDR.getId()));
    address.setStreetAddress(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_STREET_ADDR.getId()));
    address.setLocality(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_LOCALITY.getId()));
    address.setRegion(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_REGION.getId()));
    address.setPostalCode(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_POSTAL_CODE.getId()));
    address.setCountry(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_COUNTRY.getId()));
    address.setType(saasUserData.getAttributeFirstValue(CoreUserOutboundScimAttributeConstants.USER_FIELD_ADDR_TYPE.getId()));
    addresses.add(address);
    if ((address.getFormatted() != null) || 
      (address.getStreetAddress() != null) || 
      (address.getLocality() != null) || 
      (address.getRegion() != null) || 
      (address.getPostalCode() != null) || 
      (address.getCountry() != null))
    {

      user.setAddresses(addresses);
    }
    



    user.setEntitlements(createSimpleMVAttributes(saasUserData.getAttributeValues(CoreUserOutboundScimAttributeConstants.USER_FIELD_ENTITLEMENTS.getId())));
    user.setRoles(createSimpleMVAttributes(saasUserData.getAttributeValues(CoreUserOutboundScimAttributeConstants.USER_FIELD_ROLES.getId())));
    
    user.setX509Certificates(createSimpleMVAttributes(saasUserData.getAttributeValues(CoreUserOutboundScimAttributeConstants.USER_FIELD_CERTS.getId())));
    





















    List<String> schemas = new ArrayList();
    schemas.add("urn:scim:schemas:core:1.0");
    user.setSchemas(schemas);
    

    Map<String, Map<String, List<String>>> mapAttributesMap = saasUserData.getMapAttributesMap();
    if (mapAttributesMap != null)
    {
      Map<String, List<String>> rawLdapMap = (Map)mapAttributesMap.get("ldapAttributesMap");
      if (rawLdapMap != null)
      {

        Map<String, Object> ldapMap = new HashMap();
        for (Map.Entry<String, List<String>> rawLdapAttr : rawLdapMap.entrySet())
        {
          String ldapName = (String)rawLdapAttr.getKey();
          List<String> values = (List)rawLdapAttr.getValue();
          
          if (values.size() == 1)
          {
            ldapMap.put(ldapName, values.get(0));
          }
          else if (!values.isEmpty())
          {
            ldapMap.put(ldapName, values);
          }
        }
        

        user.setMap(ldapMap);
      }
    }
    
    if (getSpConnection() != null) {
      ProvisionerConfig provisionerConfig = (ProvisionerConfig)getSpConnection().getModuleConfiguration(ProvisionerConfig.class);
      

      if ((provisionerConfig != null) && 
        (provisionerConfig.getCustomScim() != null) && 
        (provisionerConfig.getCustomScim().getAttributes() != null) && 
        (provisionerConfig.getCustomScim().getSchemas() != null) && 
        (provisionerConfig.getCustomScim().getSchemas().size() > 0))
      {

        List<String> customAttributesInDotNotation = findCustomAttributes(saasUserData, provisionerConfig);
        addCustomAttributesToUser(user.getAnyAttributes(), provisionerConfig.getCustomScim(), customAttributesInDotNotation, saasUserData);
        

        if ((provisionerConfig.getCustomScim() != null) && (provisionerConfig.getCustomScim().getSchemas() != null) && (provisionerConfig.getCustomScim().getSchemas().iterator() != null)) {
          String schema = (String)provisionerConfig.getCustomScim().getSchemas().iterator().next();
          
          List<String> existingSchemas = user.getSchemas();
          existingSchemas.add(schema);
          user.setSchemas(existingSchemas);
        }
      }
    }
    
    return user;
  }
  

























  private void addComplexMultiValue(Map<String, Object> attributeMap, Schema schema, SaasUserData saasUserData, String[] parts, String dotNotation)
  {
    List<String> values = (List)saasUserData.getAttributeMap().get(dotNotation);
    String value = (String)values.iterator().next();
    String type = parts[1];
    List<Map<String, Object>> subAttributesList;
    if (attributeMap.containsKey(parts[0])) {
      List<Map<String, Object>> subAttributesList = (List)attributeMap.get(parts[0]);
      boolean foundType = false;
      for (Map<String, Object> subAttributeObject : subAttributesList) {
        if (subAttributeObject.get("type").equals(type))
        {
          subAttributeObject.put(parts[2], value);
          foundType = true;
        }
      }
      if (!foundType) {
        Map<String, Object> subAttributes = new HashMap();
        subAttributes.put(parts[2], value);
        subAttributes.put("type", parts[1]);
        subAttributesList.add(subAttributes);
      }
    } else {
      subAttributesList = new ArrayList();
      Map<String, Object> subAttributes = new HashMap();
      subAttributes.put(parts[2], value);
      subAttributes.put("type", parts[1]);
      subAttributesList.add(subAttributes);
    }
    
    attributeMap.put(parts[0], subAttributesList);
  }
  





  private void addComplexNonMultiValue(Map<String, Object> attributeMap, Schema schema, SaasUserData saasUserData, String[] parts, String dotNotation)
  {
    Map<String, Object> subAttributeMap = new HashMap();
    List<String> values = (List)saasUserData.getAttributeMap().get(dotNotation);
    
    if (attributeMap.containsKey(parts[0])) {
      subAttributeMap = (Map)attributeMap.get(parts[0]);
    }
    
    subAttributeMap.put(parts[1], values.get(0));
    
    attributeMap.put(parts[0], subAttributeMap);
  }
  










  private void addSimpleAttribute(Map<String, Object> attributeMap, Schema schema, SaasUserData saasUserData, String[] parts, String dotNotation)
  {
    SchemaAttribute attr = schema.findAttribute(parts[0]);
    if (attr != null) {
      if (attr.isMultiValued().booleanValue()) {
        List<String> values = (List)saasUserData.getAttributeMap().get(dotNotation);
        attributeMap.put(attr.getName(), values);
      } else {
        List<String> values = (List)saasUserData.getAttributeMap().get(dotNotation);
        if (values != null) {
          attributeMap.put(attr.getName(), values.get(0));
        }
      }
    }
  }
  
  private void addCustomAttributesToUser(Map<String, Object> customAttributes, Schema schema, List<String> customAttributesInDotNotation, SaasUserData saasUserData) {
    Map<String, Object> attributeMap = new HashMap();
    
    for (String dotNotation : customAttributesInDotNotation) {
      String[] parts = dotNotation.split("\\.");
      if (parts.length == 3) {
        addComplexMultiValue(attributeMap, schema, saasUserData, parts, dotNotation);
      } else if (parts.length == 2) {
        addComplexNonMultiValue(attributeMap, schema, saasUserData, parts, dotNotation);
      } else if (parts.length == 1) {
        addSimpleAttribute(attributeMap, schema, saasUserData, parts, dotNotation);
      }
    }
    
    if ((attributeMap == null) || (attributeMap.isEmpty()))
    {
      return;
    }
    
    if ((schema.getSchemas() != null) && (schema.getSchemas().iterator() != null)) {
      customAttributes.put(schema.getSchemas().iterator().next(), attributeMap);
    }
    else {
      customAttributes.put("urn:scim:schemas:extension:custom:1.0", attributeMap);
    }
  }
  
  private List<String> findCustomAttributes(SaasUserData saasUserData, ProvisionerConfig provisionerConfig)
  {
    Schema schema = provisionerConfig.getCustomScim();
    List<String> sortedAttributeIds = new ArrayList();
    List<String> customAttributes = new ArrayList();
    
    sortedAttributeIds.addAll(CustomAttributesUtil.getCustomAttributeIdsWithDotNotation(schema));
    
    for (String dotNotation : saasUserData.getAttributeMap().keySet()) {
      if (sortedAttributeIds.contains(dotNotation)) {
        customAttributes.add(dotNotation);
      }
    }
    
    return customAttributes;
  }
  



  private <T extends MultiValuedAttribute> T getPrimary(List<T> list)
  {
    T primary = (MultiValuedAttribute)list.get(0);
    for (T mva : list)
    {
      Boolean isPrimary = mva.isPrimary();
      if ((isPrimary != null) && (isPrimary.booleanValue()))
      {
        primary = mva;
        break;
      }
    }
    
    return primary;
  }
  



  private Address getPrimaryAddress(List<Address> addresses)
  {
    Address primary = (Address)addresses.get(0);
    for (Address address : addresses)
    {
      Boolean isPrimary = address.isPrimary();
      if ((isPrimary != null) && (isPrimary.booleanValue()))
      {
        primary = address;
        break;
      }
    }
    
    return primary;
  }
  
  private String getResourceUrl(String baseUrl, String id) throws SaasPluginException
  {
    if (id == null)
    {
      throw new SaasPluginException("Unable to retrieve resource.  Id is null.");
    }
    
    id = Util.urlEncodeUTF8(id);
    
    try
    {
      resourceUrlBuilder = new URIBuilder(baseUrl);
    }
    catch (URISyntaxException e) {
      URIBuilder resourceUrlBuilder;
      throw new SaasPluginException(e);
    }
    URIBuilder resourceUrlBuilder;
    String path = resourceUrlBuilder.getPath();
    if (path.endsWith("/"))
    {
      path = path + id;
    }
    else
    {
      path = path + "/" + id;
    }
    resourceUrlBuilder.setPath(path);
    
    return resourceUrlBuilder.toString();
  }
  
  private void logDebugResponse(ClientResponse response)
  {
    if (!this.log.isDebugEnabled())
    {
      return;
    }
    
    StringBuffer buffer = new StringBuffer();
    buffer.append("SCIM Service Provider returned the following:\n");
    buffer.append("HTTP Status Code: ").append(response.getStatus()).append('\n');
    buffer.append("HTTP Headers:\n");
    MultivaluedMap<String, String> headers = response.getHeaders();
    for (Map.Entry<String, List<String>> e : headers.entrySet())
    {
      header = (String)e.getKey();
      for (String value : (List)e.getValue())
      {

        buffer.append('\t').append(header).append(": ").append(value).append("\n");
      }
    }
    String header;
    this.log.debug(buffer.toString());
  }
  










  private <T extends Resource> T provisionResource(T resource, Class<T> resourceClass, String resourceUrl, String resourceName, boolean updateOperation, boolean usePatch, boolean mergeMembership, boolean maskUsername)
    throws SaasPluginException
  {
    WebResource webResource = this.restClient.resource(resourceUrl);
    


    WebResource.Builder requestBuilder = (WebResource.Builder)webResource.accept(new String[] { "application/json" }).type("application/json");
    ClientResponse response;
    ClientResponse response;
    if (updateOperation) {
      ClientResponse response;
      if ((usePatch) && (mergeMembership))
      {
        requestBuilder.header("X-HTTP-Method-Override", "PATCH");
        response = (ClientResponse)requestBuilder.post(ClientResponse.class, resource);
      }
      else
      {
        response = (ClientResponse)requestBuilder.put(ClientResponse.class, resource);
      }
    }
    else
    {
      response = (ClientResponse)requestBuilder.post(ClientResponse.class, resource);
    }
    

    int statusCode = response.getStatus();
    Response.Status status = Response.Status.fromStatusCode(statusCode);
    if ((statusCode == 405) && (usePatch) && (this.log.isErrorEnabled()))
    {
      this.log.error("SCIM service provider does not support PATCH! Reconfigure your connection to disable PATCH support");
    }
    
    if ((status == null) || (status.getFamily() != Response.Status.Family.SUCCESSFUL))
    {
      String maskedName = getMaskedUsername(resourceName, maskUsername);
      String errorMessage = "Unable to provision resource '" + maskedName + "'. Server returned status '" + response.getStatus() + "'";
      if (this.log.isErrorEnabled())
      {
        this.log.error(errorMessage + " with response: " + (String)response.getEntity(String.class));
      }
      
      SaasPluginException exception = new SaasPluginException(errorMessage);
      
      if ((this.rateLimitErrorCode != null) && (this.rateLimitErrorCode.intValue() == statusCode))
      {
        exception.setStopSession(true);
        this.log.error("Stopping provisioning cycle.");
      }
      
      throw exception;
    }
    
    logDebugResponse(response);
    
    return (Resource)response.getEntity(resourceClass);
  }
  
  private Group provisionGroup(Group group, String resourceUrl, boolean updateOperation, boolean mergeMembership) throws SaasPluginException
  {
    Group returnedGroup = (Group)provisionResource(group, Group.class, resourceUrl, group.getDisplayName(), updateOperation, this.isPatchSupported, mergeMembership, false);
    

    if (((returnedGroup == null) || (returnedGroup.getId() == null)) && (this.log.isWarnEnabled()))
    {
      this.log.warn("Group was provisioned, but the SCIM Service Provider returned a group with a null ID! This violates SCIM standards. This may affect future provisioning attempts.");
    }
    
    return returnedGroup;
  }
  
  private UserWithCustomAttributes provisionUser(UserWithCustomAttributes user, String resourceUrl, boolean updateOperation, boolean maskUsername) throws SaasPluginException
  {
    UserWithCustomAttributes returnedUser = (UserWithCustomAttributes)provisionResource(user, UserWithCustomAttributes.class, resourceUrl, user.getUserName(), updateOperation, false, false, maskUsername);
    

    if (((returnedUser == null) || (returnedUser.getId() == null)) && (this.log.isWarnEnabled()))
    {
      this.log.warn("User was provisioned, but the SCIM Service Provider returned a user with a null ID! This violates SCIM standards. This may affect future provisioning attempts.");
    }
    
    return returnedUser;
  }
  


  private Group queryGroup(SaasGroupData saasGroup)
    throws SaasPluginException
  {
    WebResource groupResource = this.restClient.resource(getResourceUrl(this.groupsUrl, saasGroup.getGuid()));
    
    if (this.log.isInfoEnabled())
    {
      this.log.info("Checking if group '" + saasGroup.getName() + "' exists on the Service Provider");
    }
    


    ClientResponse response = (ClientResponse)groupResource.accept(new String[] { "application/json" }).get(ClientResponse.class);
    

    Response.Status httpStatus = Response.Status.fromStatusCode(response.getStatus());
    

    if (httpStatus == Response.Status.NOT_FOUND)
    {
      if (this.log.isInfoEnabled())
      {
        this.log.info("Group '" + saasGroup.getName() + "' does not exist");
      }
      
      return null;
    }
    
    if (httpStatus.getFamily() != Response.Status.Family.SUCCESSFUL)
    {
      String errorMessage = "Unable to get group '" + saasGroup.getName() + "'. Server returned status '" + response.getStatus() + "'";
      if (this.log.isErrorEnabled())
      {
        this.log.error(errorMessage + " with response: " + (String)response.getEntity(String.class));
      }
      
      throw new SaasPluginException(errorMessage);
    }
    
    logDebugResponse(response);
    
    if (this.log.isInfoEnabled())
    {
      this.log.info("Group '" + saasGroup.getName() + "' exists");
    }
    
    return (Group)response.getEntity(Group.class);
  }
  
  public boolean doesGroupExist(SaasGroupData saasGroup)
    throws SaasPluginException
  {
    if (saasGroup.hasGuid())
    {
      return queryGroup(saasGroup) != null;
    }
    

    return false;
  }
  

  public String updateGroup(SaasGroupData saasGroup, boolean mergeMembership)
    throws SaasPluginException
  {
    Group group = createGroupPojo(saasGroup);
    
    if (this.log.isInfoEnabled())
    {
      this.log.info("Attempting to update SCIM 1.1 Group...");
    }
    
    provisionGroup(group, getResourceUrl(this.groupsUrl, saasGroup.getGuid()), true, mergeMembership);
    
    if (this.log.isInfoEnabled())
    {
      this.log.info("Group '" + saasGroup.getName() + "' was successfully updated on the SCIM Service Provider");
    }
    return saasGroup.getGuid();
  }
  
  public String createGroup(SaasGroupData saasGroup)
    throws SaasPluginException
  {
    Group group = createGroupPojo(saasGroup);
    
    if (this.log.isInfoEnabled())
    {
      this.log.info("Attempting to create SCIM 1.1 Group...");
    }
    
    Group returnedGroup = provisionGroup(group, this.groupsUrl, false, false);
    
    if (this.log.isInfoEnabled())
    {
      this.log.info("Group '" + saasGroup.getName() + "' was successfully created on the SCIM Service Provider");
    }
    
    return returnedGroup != null ? returnedGroup.getId() : null;
  }
  
  public void deleteGroup(SaasGroupData saasGroup)
    throws SaasPluginException
  {
    WebResource webResource = this.restClient.resource(getResourceUrl(this.groupsUrl, saasGroup.getGuid()));
    
    WebResource.Builder requestBuilder = (WebResource.Builder)webResource.accept(new String[] { "application/json" }).type("application/json");
    ClientResponse response = (ClientResponse)requestBuilder.delete(ClientResponse.class);
    

    Response.Status httpStatus = Response.Status.fromStatusCode(response.getStatus());
    if ((httpStatus.getFamily() != Response.Status.Family.SUCCESSFUL) && (httpStatus != Response.Status.NOT_FOUND))
    {
      String errorMessage = "Unable to delete resource '" + saasGroup.getName() + "'. Server returned status '" + response.getStatus() + "'";
      if (this.log.isErrorEnabled())
      {
        this.log.error(errorMessage + " with response: " + (String)response.getEntity(String.class));
      }
      
      throw new SaasPluginException(errorMessage);
    }
    
    logDebugResponse(response);
    
    if (this.log.isInfoEnabled())
    {
      this.log.info("Successfully deleted resource '" + saasGroup.getName() + "'");
    }
  }
  

  public boolean isConfiguredForGroups()
  {
    return !StringUtils.isEmpty(this.groupsUrl);
  }
  

  public boolean isUsingDnAsGroupName()
  {
    return this.usingDnAsGroupName;
  }
  

  public boolean hasLocalFieldsInfo()
  {
    return true;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\provisioner\saas\scim11serviceprovider\Scim11ServiceProviderPlugin.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */