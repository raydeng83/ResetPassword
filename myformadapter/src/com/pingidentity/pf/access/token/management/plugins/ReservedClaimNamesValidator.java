package com.pingidentity.pf.access.token.management.plugins;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.validation.FieldValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;












public class ReservedClaimNamesValidator
  implements FieldValidator
{
  private final Set<String> reserved = new HashSet(Arrays.asList(new String[] { "exp", "nbf", "iat", "iss", "aud", "sub", "jti", "typ" }));
  

  public void validate(Field field)
    throws ValidationException
  {
    String value = field.getValue();
    if (this.reserved.contains(value))
    {
      throw new ValidationException("'" + field.getName() + "' cannot use one of the JWT Reserved Claim Names " + this.reserved + ".");
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\access\token\management\plugins\ReservedClaimNamesValidator.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */