package com.pingidentity.adapters.htmlform.pwdreset.util;

import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.model.GeneratedCode;
import com.unboundid.util.StaticUtils;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.sourceid.common.ByteUtil;
import org.sourceid.common.IDGenerator;
import org.sourceid.util.log.AttributeMap;











public final class CodeGenerationUtil
{
  private static final int ITERATIONS = 10000;
  private static final int KEY_LENGTH = 256;
  
  private static byte[] hash(char[] password, byte[] salt)
  {
    PBEKeySpec spec = new PBEKeySpec(password, salt, 10000, 256);
    Arrays.fill(password, '\000');
    try {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      return skf.generateSecret(spec).getEncoded();
    } catch (NoSuchAlgorithmException|InvalidKeySpecException e) {
      throw new AssertionError("Error while hashing a password: " + e.getMessage(), e);
    } finally {
      spec.clearPassword();
    }
  }
  









  public static boolean isExpectedPassword(char[] password, byte[] salt, byte[] expectedHash)
  {
    byte[] pwdHash = hash(password, salt);
    Arrays.fill(password, '\000');
    return ByteUtil.secureEquals(pwdHash, expectedHash);
  }
  



  public static GeneratedCode getGeneratedCode(PasswordManagementConfiguration configuration)
  {
    String code = configuration.getResetType().equals("SMS") ? IDGenerator.rndNumeric(configuration.getCodeNumberOfCharacters()) : IDGenerator.rndAlphaNumeric(configuration.getCodeNumberOfCharacters());
    
    String salt = IDGenerator.rndAlphaNumeric(16);
    
    byte[] saltedCode = hash(code.toCharArray(), salt.getBytes(StandardCharsets.UTF_8));
    String saltedCodeString = DatatypeConverter.printBase64Binary(saltedCode);
    
    Date now = new Date();
    
    AttributeMap attrMap = new AttributeMap();
    attrMap.put("prCodeMapCode", saltedCodeString);
    attrMap.put("prCodeMapTime", StaticUtils.encodeGeneralizedTime(now));
    attrMap.put("prCodeMapSalt", DatatypeConverter.printBase64Binary(salt.getBytes(StandardCharsets.UTF_8)));
    
    return new GeneratedCode(attrMap, code);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdrese\\util\CodeGenerationUtil.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */