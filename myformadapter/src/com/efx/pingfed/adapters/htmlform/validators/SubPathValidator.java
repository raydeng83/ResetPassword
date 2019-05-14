package com.efx.pingfed.adapters.htmlform.validators;

import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.validation.FieldValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;


public class SubPathValidator
  implements FieldValidator
{
  private static final long serialVersionUID = 1L;
  
  public void validate(Field field)
    throws ValidationException
  {
    if ((field.getValue() != null) && (!field.getValue().equals("")))
    {
      if (!field.getValue().startsWith("/"))
      {
        throw new ValidationException("'" + field.getName() + "' must start with a /.");
      }
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\validators\SubPathValidator.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */