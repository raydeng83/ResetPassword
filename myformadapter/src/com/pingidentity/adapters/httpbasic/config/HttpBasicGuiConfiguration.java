package com.pingidentity.adapters.httpbasic.config;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.PasswordCredentialValidatorFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TableDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;
import org.sourceid.saml20.adapter.gui.validation.impl.IntegerValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;




public class HttpBasicGuiConfiguration
{
  public static final String FIELD_REALM = "Realm";
  public static final String DESC_REALM = "Authentication Realm: a name associated with the protected area.";
  public static final String FIELD_RETRIES = "Challenge Retries";
  public static final String DESC_RETRIES = "Number of allowed login attempts";
  public static final String ATTR_NAME_USERID = "username";
  public static final String MAX_CHALLENGE_DEFAULT = "3";
  
  public AdapterConfigurationGuiDescriptor getGuiDescriptor()
  {
    AdapterConfigurationGuiDescriptor guiDescriptor = new AdapterConfigurationGuiDescriptor();
    
    TextFieldDescriptor headerField = new TextFieldDescriptor("Realm", "Authentication Realm: a name associated with the protected area.");
    headerField.addValidator(new RequiredFieldValidator());
    guiDescriptor.addField(headerField);
    
    TableDescriptor pcvTable = new TableDescriptor("Credential Validators", "A list of Password Credential Validators to be used for authentication.");
    
    guiDescriptor.addTable(pcvTable);
    PasswordCredentialValidatorFieldDescriptor pcvField = new PasswordCredentialValidatorFieldDescriptor("Password Credential Validator Instance", "");
    
    pcvField.addValidator(new RequiredFieldValidator());
    pcvTable.addRowField(pcvField);
    
    TextFieldDescriptor retries = new TextFieldDescriptor("Challenge Retries", "Number of allowed login attempts");
    retries.addValidator(new RequiredFieldValidator());
    retries.addValidator(new IntegerValidator(1, 100));
    retries.setDefaultValue("3");
    guiDescriptor.addField(retries);
    
    guiDescriptor.addValidator(new ConfigurationValidator()
    {
      public void validate(Configuration configuration)
        throws ValidationException
      {
        Set<String> pcvs = new HashSet();
        List<String> errors = new ArrayList();
        Table table = configuration.getTable("Credential Validators");
        List<Row> rows = table.getRows();
        
        if (rows.isEmpty())
        {
          throw new ValidationException("Please add at least one password credential validator.");
        }
        
        for (Row row : rows)
        {
          String pcv = row.getFieldValue("Password Credential Validator Instance");
          if (!pcvs.add(pcv))
          {
            errors.add("Duplicate validator added: " + pcv);
          }
        }
        
        if (!errors.isEmpty())
        {
          throw new ValidationException(errors);
        }
        
      }
    });
    return guiDescriptor;
  }
  

  public Set<String> createAttributeContract()
  {
    Set<String> attrNames = new HashSet();
    attrNames.add("username");
    return attrNames;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\httpbasic\config\HttpBasicGuiConfiguration.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */