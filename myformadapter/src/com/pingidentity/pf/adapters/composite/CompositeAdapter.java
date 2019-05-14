package com.pingidentity.pf.adapters.composite;

import com.pingidentity.pf.adapters.composite.state.AllAttributesState;
import com.pingidentity.pf.adapters.composite.state.LoginState;
import com.pingidentity.pf.adapters.composite.state.LogoutState;
import com.pingidentity.sdk.AuthnAdapterResponse;
import com.pingidentity.sdk.AuthnAdapterResponse.AUTHN_STATUS;
import com.pingidentity.sdk.IdpAuthenticationAdapterV2;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.conf.FieldList;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.gui.AbstractSelectionFieldDescriptor.OptionValue;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.RadioGroupFieldDescriptor;
import org.sourceid.saml20.adapter.gui.SelectFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TableDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.event.PreRenderCallback;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.EnhancedRowValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthenticationAdapter;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthnAdapterDescriptor;
import org.sourceid.saml20.adapter.state.TransactionalStateSupport;
import org.sourceid.saml20.domain.AttributeContract;
import org.sourceid.saml20.domain.AuthorizationException;
import org.sourceid.saml20.domain.IdpAuthnAdapterInstance;
import org.sourceid.saml20.domain.mgmt.AdapterManager;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.profiles.idp.AuthnSourceSupport;
import org.sourceid.saml20.service.AdapterAuthnSourceKey;
import org.sourceid.saml20.service.AuthnSourceKey;
import org.sourceid.saml20.state.StateSupport;
import org.sourceid.util.log.AttributeMap;
import org.sourceid.websso.AuditLogger;
import org.sourceid.websso.AuditLogger.MDC_KEY;
import org.sourceid.websso.profiles.idp.IdpAuditLogger;

public class CompositeAdapter implements IdpAuthenticationAdapterV2, org.sourceid.saml20.domain.mgmt.impl.AdapterUser
{
  Log log = LogFactory.getLog(getClass());
  
  private static final String ADAPTER_NAME = "Composite Adapter";
  
  public static final String TABLE_ADAPTERS = "Adapters";
  
  public static final String FIELD_ADAPTER_INSTANCE = "Adapter Instance";
  
  private static final String DESC_CONFIG = "A Composite Adapter allows existing adapter instances to be chained together to execute in sequence. Each configured instance of a Composite Adapter is treated as a single logical adapter instance.";
  
  private static final String TABLE_SYNONYMS = "Attribute Name Synonyms";
  
  private static final String FIELD_NAME = "Name";
  
  private static final String LOGGED_IN_ADAPTERS = "loggedInAdapters";
  
  private static final String POLICY = "Policy";
  
  private static final String TABLE_TWO_FACTOR = "Input User Id Mapping";
  private static final String TABLE_TWO_FACTOR_LABEL = "Input User ID Mapping";
  private static final String FIELD_TWO_FACTOR_ADAPTERS = "Target Adapter";
  private static final String FIELD_TWO_FACTOR_USER_ID = "User Id Selection";
  private static final String FIELD_TWO_FACTOR_USER_ID_LABEL = "User ID Selection";
  private static final String FIELD_AUTHN_CTX_WEIGHT = "AuthN Context Weight";
  private static final String FIELD_AUTHN_CTX_OVERRIDE = "AuthN Context Override";
  private static final String FIELD_ATTR_INSERTION = "Attribute Insertion";
  private static final String DESC_TWO_FACTOR = "Create mappings";
  private static final String DESC_SYNONYMS = "Create synonyms between adapter attributes";
  private static final String DESC_ADAPTERS = "Chained adapters";
  private static final String FIELD_SYNONYM = "Synonym";
  private static final String ERR_TWO_FACTOR_MAPPING = "Target Adapter mapping exists but there is no Target Adaptor added";
  private static final String addToFrontOption = "Add To Front";
  private static final String addToBackOption = "Add To Back";
  private static final String DESC_ATTR_INSERTION = "Defines the order in which different values are returned for the same attribute name.";
  private static final String KEY_ENABLE_TARGET_ADAPTER = "pf.server.enable.target.adapter";
  private final Map<String, String> synonyms = new HashMap();
  private final Map<String, String> twoFactorMapping = new HashMap();
  private final Map<String, Integer> authnCtxWeights = new HashMap();
  private final Map<String, String> authnCtxOverrides = new HashMap();
  private boolean addToBackAttributeInsertion = true;
  private StateSupport stateSupport;
  private Configuration c;
  private static final String ALL_ATTRIBUTES_STATE_NAME = "allAttributesState";
  private static final String LOGOUT_STATE_NAME = "logoutState";
  
  private static enum Policy { Required, 
    Sufficient;
    


    private Policy() {}
  }
  

  public CompositeAdapter()
  {
    this(new StateSupport(org.sourceid.saml20.metadata.MetaDataFactory.getLocalMetaData()));
  }
  





  protected CompositeAdapter(StateSupport stateSupport)
  {
    this.stateSupport = stateSupport;
  }
  

  public AuthnAdapterResponse lookupAuthN(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters)
    throws IOException, AuthnAdapterException
  {
    String resumePath = (String)inParameters.get("com.pingidentity.adapter.input.parameter.resume.path");
    String instanceId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.instanceid");
    TransactionalStateSupport txStateSupport = new TransactionalStateSupport(resumePath);
    LoginState loginState = (LoginState)txStateSupport.getAttribute((String)inParameters.get("com.pingidentity.adapter.input.parameter.instanceid"), req, resp);
    
    if (loginState == null)
    {
      loginState = new LoginState();
    }
    
    AllAttributesState allAttributesState = (AllAttributesState)txStateSupport.getAttribute(generateAllAttributesStateId(instanceId), req, resp);
    
    if (allAttributesState == null)
    {
      allAttributesState = new AllAttributesState();
    }
    
    List<Row> rows = this.c.getTable("Adapters").getRows();
    Row row = (Row)rows.get(loginState.adapterIdx);
    String currentAdapterid = row.getFieldValue("Adapter Instance");
    IdpAuthenticationAdapter authenticationAdapter = MgmtFactory.getAdapterManager().getIdpAuthnAdapter(currentAdapterid);
    IdpAuthnAdapterInstance currentAdapterInstance = MgmtFactory.getAdapterManager().getIdpAuthnAdapterInstance(currentAdapterid);
    
    boolean isCompositeAdapter = false;
    AuthnAdapterResponse adapterResponse; if ((authenticationAdapter instanceof IdpAuthenticationAdapterV2))
    {

      IdpAuthenticationAdapterV2 adapterV2 = (IdpAuthenticationAdapterV2)authenticationAdapter;
      isCompositeAdapter = isCompositeAdapter(currentAdapterInstance);
      


      String userIdAttributeKey = (String)this.twoFactorMapping.get(currentAdapterInstance.getName());
      boolean overrideInputUserId = userIdAttributeKey != null;
      userIdAttributeKey = getSynonym(userIdAttributeKey);
      
      String userIdAttribute = null;
      if (allAttributesState.attributes.get(userIdAttributeKey) != null)
      {
        userIdAttribute = ((AttributeValue)allAttributesState.attributes.get(userIdAttributeKey)).getValue();
      }
      
      txStateSupport.setAttribute((String)inParameters.get("com.pingidentity.adapter.input.parameter.instanceid"), loginState, req, resp);
      
      txStateSupport.setAttribute(generateAllAttributesStateId(instanceId), allAttributesState, req, resp);
      


      Map<String, Object> inParametersCopy = new HashMap(inParameters);
      
      if ((!isCompositeAdapter) && (overrideInputUserId))
      {

        inParametersCopy.put("com.pingidentity.adapter.input.parameter.userid", userIdAttribute);
      }
      
      inParametersCopy.put("com.pingidentity.adapter.input.parameter.instanceid", currentAdapterid);
      
      allAttributesState.attributes.put("allAttributesState", userIdAttribute);
      
      inParametersCopy.put("com.pingidentity.adapter.input.parameter.chained.attributes", allAttributesState.attributes);
      

      this.log.info(loginState.adapterIdx + " calling lookupAuthN on adapterId=" + currentAdapterid);
      try
      {
        adapterResponse = adapterV2.lookupAuthN(req, resp, inParametersCopy);
      }
      catch (Exception e) {
        AuthnAdapterResponse adapterResponse;
        this.log.error("adapter: '" + currentAdapterid + "' exception during authentication: ", e);
        AuthnAdapterResponse adapterResponse = new AuthnAdapterResponse();
        adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.FAILURE);
      }
      
    }
    else
    {
      String entityId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.partner.entityid");
      AuthnPolicy authnPolicy = (AuthnPolicy)inParameters.get("com.pingidentity.adapter.input.parameter.authn.policy");
      Map map = null;
      this.log.info(loginState.adapterIdx + " calling lookupAuthN on adapterId=" + currentAdapterid);
      try
      {
        map = authenticationAdapter.lookupAuthN(req, resp, entityId, authnPolicy, resumePath);
      }
      catch (Exception e)
      {
        this.log.error("adapter: '" + currentAdapterid + "' exception during authentication: ", e);
        AuthnAdapterResponse adapterResponse = new AuthnAdapterResponse();
        adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.FAILURE);
      }
      
      adapterResponse = new AuthnAdapterResponse();
      adapterResponse.setAttributeMap(map);
      
      if (resp.isCommitted())
      {
        adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.IN_PROGRESS);
      }
      else
      {
        adapterResponse.setAuthnStatus((map == null) || (map.isEmpty()) ? AuthnAdapterResponse.AUTHN_STATUS.FAILURE : AuthnAdapterResponse.AUTHN_STATUS.SUCCESS);
      }
    }
    

    auditAuthnAttempt(adapterResponse, currentAdapterid, resp);
    
    if (adapterResponse.getAuthnStatus() != AuthnAdapterResponse.AUTHN_STATUS.IN_PROGRESS)
    {
      if (com.pingidentity.common.util.AdapterUtils.adapterNeedsPathRandomization(currentAdapterInstance))
      {



        resumePath = this.stateSupport.insertNonce(resumePath);
      }
    }
    
    AttributeMap adapterResultMap = null;
    if (adapterResponse.getAttributeMap() != null)
    {
      try
      {

        adapterResultMap = getAdapterResultMap(adapterResponse.getAttributeMap(), currentAdapterid, req);
      }
      catch (AuthorizationException e)
      {
        this.log.info("adapter: '" + currentAdapterid + "' failed issuance criteria: " + e.getMessage());
        adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.FAILURE);
      }
    }
    
    if (adapterResponse.getAuthnStatus() == AuthnAdapterResponse.AUTHN_STATUS.SUCCESS)
    {
      try
      {
        loginState.adapterIdx += 1;
        
        adapterResultMap = addAuthnCtxOverride(adapterResultMap, currentAdapterid);
        

        allAttributesState.attributes.put(currentAdapterid, adapterResponse.getAttributeMap());
        allAttributesState.attributes = mergeAttributes(allAttributesState, adapterResultMap);
        
        sortAuthnCtxByWeight(allAttributesState, currentAdapterid, adapterResultMap);
      }
      catch (NullPointerException e)
      {
        throw new AuthnAdapterException("Resulting AttributeMap with a SUCCESS status should not be null.");
      }
      inParameters.put("com.pingidentity.adapter.input.parameter.chained.attributes", allAttributesState.attributes);
      

      txStateSupport.setAttribute(generateAllAttributesStateId(instanceId), allAttributesState, req, resp);
      
      if (!isCompositeAdapter)
      {

        if (allAttributesState.attributes.get("loggedInAdapters") == null)
        {
          allAttributesState.attributes.put("loggedInAdapters", new AttributeValue(currentAdapterid));
        }
        else
        {
          List<String> loggedInAdapters = new ArrayList(((AttributeValue)allAttributesState.attributes.get("loggedInAdapters")).getValuesAsCollection());
          loggedInAdapters.add(currentAdapterid);
          allAttributesState.attributes.put("loggedInAdapters", new AttributeValue(loggedInAdapters));
        }
      }
      
      if ((row.getField("Policy").getValue().equals(Policy.Sufficient.toString())) || 
        (loginState.adapterIdx >= rows.size()))
      {
        Map<String, Object> objectHashMap = new HashMap();
        objectHashMap.putAll(allAttributesState.attributes);
        adapterResponse.setAttributeMap(objectHashMap);
        txStateSupport.removeAttribute(generateAllAttributesStateId(instanceId), req, resp);
        txStateSupport.removeAttribute((String)inParameters.get("com.pingidentity.adapter.input.parameter.instanceid"), req, resp);

      }
      else
      {
        adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.IN_PROGRESS);
        txStateSupport.setAttribute((String)inParameters.get("com.pingidentity.adapter.input.parameter.instanceid"), loginState, req, resp);
        
        txStateSupport.setAttribute(generateAllAttributesStateId(instanceId), allAttributesState, req, resp);
        resp.sendRedirect(resumePath);
      }
    }
    else if (adapterResponse.getAuthnStatus() == AuthnAdapterResponse.AUTHN_STATUS.FAILURE)
    {

      if (row.getField("Policy").getValue().equals(Policy.Required.toString()))
      {

        adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.FAILURE);
        txStateSupport.removeAttribute(generateAllAttributesStateId(instanceId), req, resp);
        txStateSupport.removeAttribute((String)inParameters.get("com.pingidentity.adapter.input.parameter.instanceid"), req, resp);
        
        return adapterResponse;
      }
      

      loginState.adapterIdx += 1;
      if (loginState.adapterIdx < rows.size())
      {
        adapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.IN_PROGRESS);
        txStateSupport.setAttribute((String)inParameters.get("com.pingidentity.adapter.input.parameter.instanceid"), loginState, req, resp);
        
        txStateSupport.setAttribute(generateAllAttributesStateId(instanceId), allAttributesState, req, resp);
        
        if (!resp.isCommitted())
        {
          resp.sendRedirect(resumePath);
        }
      }
    }
    

    return adapterResponse;
  }
  

  private void auditAuthnAttempt(AuthnAdapterResponse adapterResponse, String currentAdapterid, HttpServletResponse resp)
  {
    AuditLogger.setAuthnSourceId(new AdapterAuthnSourceKey(currentAdapterid));
    if (adapterResponse.getAuthnStatus() == AuthnAdapterResponse.AUTHN_STATUS.FAILURE)
    {
      AuditLogger.put(AuditLogger.MDC_KEY.DESCRIPTION.toString(), adapterResponse.getErrorMessage());
    }
    AuditLogger.setUserName(adapterResponse.getUsername());
    IdpAuditLogger.logAuthnAttempt("Attempted authentication with adapter", adapterResponse.getAuthnStatus());
    IdpAuditLogger.cleanupAuthnAttempt();
  }
  
  private AttributeMap getAdapterResultMap(Map<String, Object> incommingMap, String adapterId, HttpServletRequest request) throws AuthnAdapterException, AuthorizationException
  {
    AuthnSourceKey authnSourceKey = new AdapterAuthnSourceKey(adapterId);
    
    return new AuthnSourceSupport().executeAdditionalMapping(authnSourceKey, incommingMap, request);
  }
  
  private String generateAllAttributesStateId(String adapterInstanceId)
  {
    return adapterInstanceId + "-" + "allAttributesState";
  }
  

  private void sortAuthnCtxByWeight(AllAttributesState allAttributesState, String adapterId, AttributeMap attributes)
  {
    String val;
    
    if (attributes.containsKey("org.sourceid.saml20.adapter.idp.authn.authnCtx"))
    {
      Integer weight = getAuthnCtxWeight(adapterId);
      if (allAttributesState.authnCtx.get(weight) == null)
      {

        AttributeValue authnCtx = new AttributeValue(((AttributeValue)attributes.get("org.sourceid.saml20.adapter.idp.authn.authnCtx")).getValue());
        allAttributesState.authnCtx.put(weight, authnCtx);

      }
      else
      {
        ArrayList<String> attrValues = new ArrayList();
        for (Iterator localIterator = ((AttributeValue)allAttributesState.authnCtx.get(weight)).getValues().iterator(); localIterator.hasNext();) { val = (String)localIterator.next();
          
          attrValues.add(val);
        }
        
        attrValues.add(((AttributeValue)attributes.get("org.sourceid.saml20.adapter.idp.authn.authnCtx")).getValue());
        allAttributesState.authnCtx.put(weight, new AttributeValue(attrValues));
      }
    }
    
    AttributeValue authnCtxList = null;
    Object attrValues; for (Integer i = Integer.valueOf(5); i.intValue() > 0; val = i = Integer.valueOf(i.intValue() - 1))
    {
      if (allAttributesState.authnCtx.get(i) != null)
      {
        if (authnCtxList == null)
        {
          authnCtxList = (AttributeValue)allAttributesState.authnCtx.get(i);
        }
        else
        {
          attrValues = new ArrayList();
          for (String val : authnCtxList.getValues())
          {
            ((ArrayList)attrValues).add(val);
          }
          
          ((ArrayList)attrValues).add(((AttributeValue)allAttributesState.authnCtx.get(i)).getValue());
          
          authnCtxList = new AttributeValue((Collection)attrValues);
        }
      }
      attrValues = i;
    }
    




















    allAttributesState.attributes.put("org.sourceid.saml20.adapter.idp.authn.authnCtx", authnCtxList);
  }
  

  public boolean isInUse(String instanceId)
  {
    if (this.c.getTable("Adapters") != null)
    {
      for (Row row : this.c.getTable("Adapters").getRows())
      {
        if (row.getField("Adapter Instance").getValue().equals(instanceId))
        {
          return true;
        }
      }
    }
    

    return false;
  }
  



  private AttributeMap addAuthnCtxOverride(AttributeMap attrMap, String adapterId)
  {
    String override = (String)this.authnCtxOverrides.get(adapterId);
    

    if ((override != null) && (!override.equals("")))
    {
      attrMap.put("org.sourceid.saml20.adapter.idp.authn.authnCtx", override);
    }
    
    return attrMap;
  }
  

  public boolean logoutAuthN(Map authnIdentifiers, HttpServletRequest req, HttpServletResponse resp, String resumePath)
    throws AuthnAdapterException, IOException
  {
    TransactionalStateSupport txStateSupport = new TransactionalStateSupport(resumePath);
    LogoutState state = (LogoutState)txStateSupport.getAttribute("logoutState", req, resp);
    if (state == null)
    {
      state = new LogoutState();
    }
    
    if (!state.waitingAdapterResponse)
    {

      resumePath = this.stateSupport.insertNonce(resumePath);
    }
    
    String currentAdapterId = (String)((AttributeValue)authnIdentifiers.get("loggedInAdapters")).getValuesAsCollection().toArray()[state.adapterIdx];
    IdpAuthenticationAdapter authenticationAdapter = MgmtFactory.getAdapterManager().getIdpAuthnAdapter(currentAdapterId);
    this.log.info(state.adapterIdx + " calling logoutAuthN on adapterId=" + currentAdapterId);
    
    boolean result = authenticationAdapter.logoutAuthN((Map)authnIdentifiers.get(currentAdapterId), req, resp, resumePath);
    
    if (resp.isCommitted())
    {
      state.waitingAdapterResponse = true;
      txStateSupport.setAttribute("logoutState", state, req, resp);
      return false;
    }
    state.waitingAdapterResponse = false;
    
    if (result)
    {
      state.numSuccesses += 1;
    }
    
    state.adapterIdx += 1;
    if (state.adapterIdx < ((AttributeValue)authnIdentifiers.get("loggedInAdapters")).getValuesAsCollection().size())
    {
      txStateSupport.setAttribute("logoutState", state, req, resp);
      resp.sendRedirect(resumePath);
      return false;
    }
    
    txStateSupport.removeAttribute("logoutState", req, resp);
    if (state.numSuccesses >= ((AttributeValue)authnIdentifiers.get("loggedInAdapters")).getValuesAsCollection().size())
    {
      return true;
    }
    

    return false;
  }
  

  public class AdapterSelectFieldDescriptor
    extends SelectFieldDescriptor
  {
    private static final long serialVersionUID = 1L;
    
    protected AdapterSelectFieldDescriptor(String name, String description)
    {
      super(description);
    }
    

    public List<AbstractSelectionFieldDescriptor.OptionValue> getOptionValues()
    {
      List<AbstractSelectionFieldDescriptor.OptionValue> options = new ArrayList();
      AdapterManager adapterManager = MgmtFactory.getAdapterManager();
      Collection<IdpAuthnAdapterInstance> instances = adapterManager.getIdpAuthnAdapterNonConnectionBasedInstances();
      for (IdpAuthnAdapterInstance instance : instances)
      {
        options.add(new AbstractSelectionFieldDescriptor.OptionValue(instance.getName(), instance.getId()));
      }
      

      options.sort(AbstractSelectionFieldDescriptor.OptionValue.NAME_COMPARATOR);
      
      options.add(0, SELECT_ONE);
      
      return options;
    }
  }
  

  public IdpAuthnAdapterDescriptor getAdapterDescriptor()
  {
    AdapterConfigurationGuiDescriptor desc = new AdapterConfigurationGuiDescriptor("A Composite Adapter allows existing adapter instances to be chained together to execute in sequence. Each configured instance of a Composite Adapter is treated as a single logical adapter instance.");
    
    TableDescriptor adaptersTable = new TableDescriptor("Adapters", "Chained adapters");
    desc.addTable(adaptersTable);
    adaptersTable.addValidator(new EnhancedRowValidator()
    {
      public void validate(FieldList fieldsInRow)
        throws ValidationException
      {}
      





      public void validate(FieldList fieldsInRow, Configuration configuration)
        throws ValidationException
      {
        String repeatedAdapter = CompositeAdapter.this.hasRepeatedFieldValue(configuration, "Adapters", "Adapter Instance");
        if (!StringUtils.isEmpty(repeatedAdapter))
        {
          throw new ValidationException("Adapter has already been added");
        }
        
      }
    });
    desc.addValidator(new ConfigurationValidator()
    {

      public void validate(Configuration configuration)
        throws ValidationException
      {
        List<String> errors = new ArrayList();
        

        Table table = configuration.getTable("Adapters");
        boolean foundVip = false;
        for (Row row : table.getRows())
        {
          String adapterId = row.getField("Adapter Instance").getValue();
          
          IdpAuthenticationAdapter authenticationAdapter = MgmtFactory.getAdapterManager().getIdpAuthnAdapter(adapterId);
          IdpAuthnAdapterInstance instance = MgmtFactory.getAdapterManager().getIdpAuthnAdapterInstance(adapterId);
          if (((authenticationAdapter instanceof IdpAuthenticationAdapterV2)) && (!CompositeAdapter.this.isCompositeAdapter(instance)))
          {
            foundVip = true;
          }
        }
        table = configuration.getTable("Input User Id Mapping");
        if ((table != null) && (table.getRows().size() > 0) && (!foundVip))
        {
          errors.add("Target Adapter mapping exists but there is no Target Adaptor added");
        }
        
        if (!errors.isEmpty())
        {
          throw new ValidationException(errors);
        }
        
      }
      
    });
    AdapterSelectFieldDescriptor adapterSelectFieldDescriptor = new AdapterSelectFieldDescriptor("Adapter Instance", "");
    adapterSelectFieldDescriptor.addValidator(new RequiredFieldValidator());
    adaptersTable.addRowField(adapterSelectFieldDescriptor);
    
    String[] options = { "Required", "Sufficient" };
    FieldDescriptor groupFieldDescriptor = new RadioGroupFieldDescriptor("Policy", "", options);
    groupFieldDescriptor.setDefaultValue(options[0]);
    groupFieldDescriptor.addValidator(new RequiredFieldValidator());
    adaptersTable.addRowField(groupFieldDescriptor);
    
    List<AbstractSelectionFieldDescriptor.OptionValue> contxOptionValues = new ArrayList();
    
    SelectFieldDescriptor contxDesc = new SelectFieldDescriptor("AuthN Context Weight", "", contxOptionValues);
    Integer localInteger1; Integer localInteger2; for (Integer i = Integer.valueOf(1); i.intValue() <= 5; localInteger2 = i = Integer.valueOf(i.intValue() + 1))
    {
      contxOptionValues.add(new AbstractSelectionFieldDescriptor.OptionValue(i.toString(), i.toString()));localInteger1 = i;
    }
    contxDesc.setOptionValues(contxOptionValues);
    contxDesc.setDefaultValue("3");
    adaptersTable.addRowField(contxDesc);
    
    TextFieldDescriptor defaultAuthnCtxDesc = new TextFieldDescriptor("AuthN Context Override", "");
    adaptersTable.addRowField(defaultAuthnCtxDesc);
    
    SelectFieldDescriptor selectFieldDescriptor1 = new SelectFieldDescriptor("Name", "", new String[0]);
    SelectFieldDescriptor selectFieldDescriptor2 = new SelectFieldDescriptor("Synonym", "", new String[0]);
    
    String[] attrSortOptions = { "Add To Back", "Add To Front" };
    FieldDescriptor attrSortDesc = new RadioGroupFieldDescriptor("Attribute Insertion", "Defines the order in which different values are returned for the same attribute name.", attrSortOptions);
    
    attrSortDesc.setDefaultValue(attrSortOptions[0]);
    attrSortDesc.addValidator(new RequiredFieldValidator());
    desc.addField(attrSortDesc);
    
    desc.addPreRenderCallback(new PreRenderCallback()
    {



      public void callback(List<FieldDescriptor> fieldDescriptors, List<FieldDescriptor> advancedFieldDescriptors, List<TableDescriptor> tableDescriptors, Configuration configuration)
      {


        SelectFieldDescriptor synonymsFieldDescriptor1 = (SelectFieldDescriptor)((TableDescriptor)tableDescriptors.get(CompositeAdapter.this.findTable(tableDescriptors, "Attribute Name Synonyms"))).getRowFields().get(0);
        
        SelectFieldDescriptor synonymsFieldDescriptor2 = (SelectFieldDescriptor)((TableDescriptor)tableDescriptors.get(CompositeAdapter.this.findTable(tableDescriptors, "Attribute Name Synonyms"))).getRowFields().get(1);
        
        Set<String> attributeNames = new TreeSet();
        Set<String> twoFactorAttributes = new TreeSet();
        Set<String> twoFactorAdapters = new TreeSet();
        
        for (Iterator localIterator1 = configuration.getTable("Adapters").getRows().iterator(); localIterator1.hasNext();) { row = (Row)localIterator1.next();
          
          AdapterManager adapterManager = MgmtFactory.getAdapterManager();
          String adapterId = row.getFieldValue("Adapter Instance");
          
          if (adapterId != null)
          {
            IdpAuthnAdapterInstance instance = adapterManager.getIdpAuthnAdapterInstance(adapterId);
            IdpAuthenticationAdapter authenticationAdapter = MgmtFactory.getAdapterManager().getIdpAuthnAdapter(adapterId);
            
            if (instance != null)
            {
              for (String name : instance.getAttributeContract().getAllAttributeNames())
              {
                twoFactorAttributes.add(name);
                attributeNames.add(name);
              }
              
              if (((authenticationAdapter instanceof IdpAuthenticationAdapterV2)) && 
                (!CompositeAdapter.this.isCompositeAdapter(instance)))
              {
                twoFactorAdapters.add(instance.getName());
              }
            }
          }
        }
        Row row;
        List<AbstractSelectionFieldDescriptor.OptionValue> twoFactorAttributeOptionValues;
        if (CompositeAdapter.this.isTwoFactorInstalled())
        {
          Object twoFactorAdapterOptionValues = new ArrayList();
          for (row = twoFactorAdapters.iterator(); row.hasNext();) { name = (String)row.next();
            
            ((List)twoFactorAdapterOptionValues).add(new AbstractSelectionFieldDescriptor.OptionValue(name, name));
          }
          
          String name;
          ((List)twoFactorAdapterOptionValues).sort(AbstractSelectionFieldDescriptor.OptionValue.NAME_COMPARATOR);
          
          ((List)twoFactorAdapterOptionValues).add(0, SelectFieldDescriptor.SELECT_ONE);
          
          twoFactorAttributeOptionValues = new ArrayList();
          
          for (String name : twoFactorAttributes)
          {
            twoFactorAttributeOptionValues.add(new AbstractSelectionFieldDescriptor.OptionValue(name, name));
          }
          
          twoFactorAttributeOptionValues.sort(AbstractSelectionFieldDescriptor.OptionValue.NAME_COMPARATOR);
          
          twoFactorAttributeOptionValues.add(0, SelectFieldDescriptor.SELECT_ONE);
          

          SelectFieldDescriptor selectFieldTwoFactorAdaptersDescriptor = (SelectFieldDescriptor)((TableDescriptor)tableDescriptors.get(CompositeAdapter.this.findTable(tableDescriptors, "Input User Id Mapping"))).getRowFields().get(0);
          
          SelectFieldDescriptor selectFieldTwoFactorAttributesDescriptor = (SelectFieldDescriptor)((TableDescriptor)tableDescriptors.get(CompositeAdapter.this.findTable(tableDescriptors, "Input User Id Mapping"))).getRowFields().get(1);
          
          selectFieldTwoFactorAdaptersDescriptor.setOptionValues((List)twoFactorAdapterOptionValues);
          selectFieldTwoFactorAttributesDescriptor.setOptionValues(twoFactorAttributeOptionValues);


        }
        else if (!System.getProperty("pf.server.enable.target.adapter", "false").equalsIgnoreCase("true"))
        {
          int idx = CompositeAdapter.this.findTable(tableDescriptors, "Input User Id Mapping");
          if (idx >= 0)
          {
            tableDescriptors.remove(idx);
          }
        }
        

        Object optionValues = new ArrayList();
        
        ((List)optionValues).add(SelectFieldDescriptor.SELECT_ONE);
        for (String name : attributeNames)
        {
          ((List)optionValues).add(new AbstractSelectionFieldDescriptor.OptionValue(name, name));
        }
        
        synonymsFieldDescriptor1.setOptionValues((List)optionValues);
        synonymsFieldDescriptor2.setOptionValues((List)optionValues);

      }
      

    });
    TableDescriptor twoFactorTable = new TableDescriptor("Input User Id Mapping", "Create mappings");
    twoFactorTable.setLabel("Input User ID Mapping");
    desc.addTable(twoFactorTable);
    
    SelectFieldDescriptor selectFieldTwoFactorAdaptersDescriptor = new SelectFieldDescriptor("Target Adapter", "", new String[0]);
    

    SelectFieldDescriptor selectFieldTwoFactorAttributesDescriptor = new SelectFieldDescriptor("User Id Selection", "", new String[0]);
    

    selectFieldTwoFactorAttributesDescriptor.setLabel("User ID Selection");
    
    selectFieldTwoFactorAdaptersDescriptor.addValidator(new RequiredFieldValidator());
    
    twoFactorTable.addValidator(new EnhancedRowValidator()
    {
      public void validate(FieldList fieldsInRow)
        throws ValidationException
      {}
      





      public void validate(FieldList fieldsInRow, Configuration configuration)
        throws ValidationException
      {
        String repeatedAdapter = CompositeAdapter.this.hasRepeatedFieldValue(configuration, "Input User Id Mapping", "Target Adapter");
        if (!StringUtils.isEmpty(repeatedAdapter))
        {
          throw new ValidationException("Input User ID already mapped for " + repeatedAdapter);
        }
        
      }
      
    });
    selectFieldTwoFactorAttributesDescriptor.addValidator(new RequiredFieldValidator());
    
    twoFactorTable.addRowField(selectFieldTwoFactorAdaptersDescriptor);
    twoFactorTable.addRowField(selectFieldTwoFactorAttributesDescriptor);
    
    TableDescriptor namesTable = new TableDescriptor("Attribute Name Synonyms", "Create synonyms between adapter attributes");
    desc.addTable(namesTable);
    
    namesTable.addValidator(new EnhancedRowValidator()
    {
      public void validate(FieldList fieldsInRow)
        throws ValidationException
      {
        if (fieldsInRow.getFieldValue("Name").equals(fieldsInRow.getFieldValue("Synonym")))
        {
          throw new ValidationException("The Name/Synonym pair is identical");
        }
      }
      
      public void validate(FieldList fieldsInRow, Configuration configuration)
        throws ValidationException
      {
        List<String> names = new ArrayList();
        for (Row row : configuration.getTable("Attribute Name Synonyms").getRows())
        {
          if (names.contains(row.getFieldValue("Name")))
          {
            throw new ValidationException("Name has already been assigned to a synonym");
          }
          names.add(row.getFieldValue("Name"));
        }
        
      }
    });
    namesTable.addRowField(selectFieldDescriptor1);
    namesTable.addRowField(selectFieldDescriptor2);
    
    desc.addValidator(new com.pingidentity.pf.adapters.composite.validators.CompositeAdapterConfigurationValidator());
    
    return new IdpAuthnAdapterDescriptor(this, "Composite Adapter", new java.util.HashSet(), true, desc, false, 
      org.sourceid.common.VersionUtil.getVersion());
  }
  
  private String hasRepeatedFieldValue(Configuration configuration, String tableName, String feildName)
  {
    List<String> encountredfieldNames = new ArrayList();
    for (Row row : configuration.getTable(tableName).getRows())
    {
      String fieldValue = row.getFieldValue(feildName);
      if (encountredfieldNames.contains(fieldValue.toUpperCase()))
      {
        return fieldValue;
      }
      encountredfieldNames.add(row.getFieldValue(feildName).toUpperCase());
    }
    return null;
  }
  

  protected boolean isTwoFactorInstalled()
  {
    for (IdpAuthnAdapterInstance instance : MgmtFactory.getAdapterManager().getIdpAuthnAdapterInstances())
    {
      IdpAuthenticationAdapter adapter = MgmtFactory.getAdapterManager().getIdpAuthnAdapter(instance.getId());
      if (((adapter instanceof IdpAuthenticationAdapterV2)) && (!isCompositeAdapter(instance)))
      {
        return true;
      }
    }
    
    return false;
  }
  
  protected int findTable(List<TableDescriptor> tableDescriptor, String name)
  {
    int ind = 0;
    Iterator<TableDescriptor> t = tableDescriptor.iterator();
    while (t.hasNext())
    {
      TableDescriptor td = (TableDescriptor)t.next();
      if (td.getName().equals(name))
      {
        return ind;
      }
      ind++;
    }
    return -1;
  }
  

  public void configure(Configuration configuration)
  {
    this.c = configuration;
    createSynonyms();
    createTwoFactorMapping();
    createAuthnCtxWeights();
    createAuthnCtxOverrides();
    createAttributeInsertion();
  }
  

  public Map<String, Object> getAdapterInfo()
  {
    return null;
  }
  
  private void addSynonym(String name, String synonym)
  {
    this.synonyms.put(synonym, name);
  }
  
  private String getSynonym(String attr)
  {
    if (this.synonyms.get(attr) == null)
    {
      return attr;
    }
    

    return (String)this.synonyms.get(attr);
  }
  

  private boolean isCompositeAdapter(IdpAuthnAdapterInstance adapter)
  {
    return adapter.getDescriptor().getPluginClassName().contains("CompositeAdapter");
  }
  
  protected Map<String, Object> mergeAttributes(AllAttributesState state, AttributeMap sourceMap)
  {
    String attrKey = null;
    
    Iterator<String> it = sourceMap.keySet().iterator();
    String attrSynonym = null;
    
    while (it.hasNext())
    {
      attrKey = (String)it.next();
      
      attrSynonym = getSynonym(attrKey);
      
      if (state.attributes.get(attrSynonym) != null)
      {


        if ((state.attributes.get(attrSynonym) instanceof AttributeValue))
        {

          Iterator<String> sourceMapValueIter = ((AttributeValue)sourceMap.get(attrKey)).getValues().iterator();
          while (sourceMapValueIter.hasNext())
          {
            String sourceMapValue = (String)sourceMapValueIter.next();
            AttributeValue valFromState = (AttributeValue)state.attributes.get(attrSynonym);
            

            if (!valueExists(sourceMapValue, valFromState))
            {
              List<String> attrValues = new ArrayList();
              for (String val : valFromState.getValues())
              {
                attrValues.add(val);
              }
              
              if (this.addToBackAttributeInsertion)
              {
                attrValues.add(sourceMapValue);
              }
              else
              {
                attrValues.add(0, sourceMapValue);
              }
              
              state.attributes.put(attrSynonym, new AttributeValue(attrValues));
            }
            
          }
        }
      }
      else {
        state.attributes.put(attrSynonym, sourceMap.get(attrKey));
      }
    }
    
    return state.attributes;
  }
  
  private boolean valueExists(String attr, AttributeValue attrValues)
  {
    for (String val : attrValues.getValues())
    {
      if (val.equals(attr))
      {
        return true;
      }
    }
    return false;
  }
  
  private void createAttributeInsertion()
  {
    if (this.c.getField("Attribute Insertion").getValue().equals("Add To Back"))
    {
      this.addToBackAttributeInsertion = true;
    }
    else
    {
      this.addToBackAttributeInsertion = false;
    }
  }
  
  private void createAuthnCtxWeights()
  {
    List<Row> rows = this.c.getTable("Adapters").getRows();
    for (Row row : rows)
    {
      if ((row.getFieldValue("AuthN Context Weight") != null) && 
        (!row.getFieldValue("AuthN Context Weight").equals("")))
      {
        this.authnCtxWeights.put(row.getFieldValue("Adapter Instance"), new Integer(row
          .getFieldValue("AuthN Context Weight")));
      }
    }
  }
  
  private void createAuthnCtxOverrides()
  {
    List<Row> rows = this.c.getTable("Adapters").getRows();
    for (Row row : rows)
    {
      this.authnCtxOverrides.put(row.getFieldValue("Adapter Instance"), row
        .getFieldValue("AuthN Context Override"));
    }
  }
  
  private Integer getAuthnCtxWeight(String adapterId)
  {
    return (Integer)this.authnCtxWeights.get(adapterId);
  }
  
  private void createTwoFactorMapping()
  {
    if (this.c.getTable("Input User Id Mapping") != null)
    {
      List<Row> rows = this.c.getTable("Input User Id Mapping").getRows();
      for (Row row : rows)
      {
        this.twoFactorMapping.put(row.getFieldValue("Target Adapter"), row
          .getFieldValue("User Id Selection"));
      }
    }
  }
  
  private void createSynonyms()
  {
    List<Row> rows = this.c.getTable("Attribute Name Synonyms").getRows();
    for (Row row : rows)
    {
      addSynonym(row.getFieldValue("Synonym"), row.getFieldValue("Name"));
    }
  }
  

  public Map lookupAuthN(HttpServletRequest req, HttpServletResponse resp, String partnerSpEntityId, AuthnPolicy authnPolicy, String resumePath)
    throws AuthnAdapterException, IOException
  {
    throw new UnsupportedOperationException();
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\adapters\composite\CompositeAdapter.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */