package com.pingidentity.pf.access.token.management.plugins;

import com.pingidentity.common.util.Base64URL;
import java.security.Key;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.conf.FieldList;
import org.sourceid.saml20.adapter.gui.validation.RowValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;



public class SymmetricKeySupport
  implements RowValidator
{
  private static final Log log = LogFactory.getLog(SymmetricKeySupport.class);
  static final int MIN_LENGTH = 16;
  
  public void validate(FieldList fieldsInRow)
    throws ValidationException
  {
    getKeyChecked(fieldsInRow);
  }
  
  static Key getKey(FieldList fieldsInRow)
  {
    try
    {
      return getKeyChecked(fieldsInRow);
    }
    catch (ValidationException e)
    {
      log.error("Unable to decode symmetric key.", e); }
    return null;
  }
  
  static Key getKeyChecked(FieldList fieldsInRow)
    throws ValidationException
  {
    String encoding = fieldsInRow.getFieldValue("Encoding");
    String kid = fieldsInRow.getFieldValue("Key ID");
    String keyName = "Key";
    String encodedKeyValue = fieldsInRow.getFieldValue(keyName);
    

    if (("".equals(encoding)) || (StringUtils.isBlank(encoding)))
    {
      try
      {
        rawKeyValue = Hex.decodeHex(encodedKeyValue.toCharArray());
      }
      catch (DecoderException e) {
        byte[] rawKeyValue;
        String errorMessage = "" + keyName + " with key id '" + kid + "' is not valid hex: " + e.getMessage();
        if (!errorMessage.endsWith("."))
        {
          errorMessage = errorMessage + ".";
        }
        throw new ValidationException(errorMessage);
      }
    } else { byte[] rawKeyValue;
      if ("b64u".equals(encoding))
      {
        rawKeyValue = Base64URL.decode(encodedKeyValue);

      }
      else
      {
        throw new ValidationException("Unrecognized encoding for symmetric key: " + encoding); }
    }
    byte[] rawKeyValue;
    if (rawKeyValue.length < 16)
    {

      throw new ValidationException("" + keyName + " with key id '" + kid + "' is " + rawKeyValue.length * 8 + " bits but needs to be" + getAtLeastBitsMessagePart(128) + ".");
    }
    
    return new SecretKeySpec(rawKeyValue, "AES");
  }
  
  static String getAtLeastBitsMessagePart(int bits)
  {
    return String.format(" at least %d bits %s", new Object[] { Integer.valueOf(bits), getBitSizeExampleMessage(bits) });
  }
  
  static String getExactBitsMessagePart(int bits)
  {
    return String.format(" exactly %d bits %s", new Object[] { Integer.valueOf(bits), getBitSizeExampleMessage(bits) });
  }
  
  private static String getBitSizeExampleMessage(int bits)
  {
    return String.format("(e.g. %d hex or %d base64url characters)", new Object[] {
      Integer.valueOf(bits / 8 * 2), 
      Integer.valueOf((int)Math.ceil(21.33333396911621D)) });
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\access\token\management\plugins\SymmetricKeySupport.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */