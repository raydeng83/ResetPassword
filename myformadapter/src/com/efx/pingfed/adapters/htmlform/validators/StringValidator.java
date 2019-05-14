package com.efx.pingfed.adapters.htmlform.validators;

import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.validation.FieldValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;


public class StringValidator
  implements FieldValidator
{
  private static final long serialVersionUID = 1L;
  public static final String EMPTY_STRING = "";
  private final String[] possibleValues;
  
  public StringValidator(String[] values)
  {
    this.possibleValues = values;
  }
  
  public void validate(Field field)
    throws ValidationException
  {
    validate(field.getName(), field.getValue());
  }
  






  public void validate(String name, String value)
    throws ValidationException
  {
    if ((value == null) || (value.trim().equals("")))
    {
      throw new ValidationException("Parameter " + name + " mustn't be empty.");
    }
    
    for (String possibleValue : this.possibleValues)
    {
      if (value.equalsIgnoreCase(possibleValue))
      {
        return;
      }
    }
    
    throw new ValidationException("Parameter " + name + " can be only " + generateValues() + '.');
  }
  
  protected StringBuffer generateValues()
  {
    StringBuffer result = new StringBuffer(this.possibleValues[0]);
    for (int i = 1; i < this.possibleValues.length; i++)
    {
      result.append(" or ");
      result.append(this.possibleValues[i]);
    }
    return result;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\validators\StringValidator.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */