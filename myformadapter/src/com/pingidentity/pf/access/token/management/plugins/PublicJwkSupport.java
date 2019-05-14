package com.pingidentity.pf.access.token.management.plugins;

import com.pingidentity.crypto.Cert;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.Factory;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey.Factory;
import org.jose4j.lang.JoseException;
import org.sourceid.common.ExceptionUtil;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.validation.FieldValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;


public class PublicJwkSupport
  implements FieldValidator
{
  private static final Log log = LogFactory.getLog(PublicJwkSupport.class);
  
  public void validate(Field field)
    throws ValidationException
  {
    getKeyChecked(field);
  }
  
  public static PublicJsonWebKey getKey(Field field)
  {
    try
    {
      return getKeyChecked(field);
    }
    catch (ValidationException e)
    {
      throw new IllegalStateException("Problem with asymmetric encryption public key.", e);
    }
  }
  
  private static PublicJsonWebKey getKeyChecked(Field field)
    throws ValidationException
  {
    if ((field != null) && (StringUtils.isNotBlank(field.getValue())))
    {
      String value = field.getValue();
      String name = field.getName();
      try
      {
        value = value.trim();
        if ((value.startsWith("-----BEGIN CERTIFICATE-----")) && (value.endsWith("-----END CERTIFICATE-----")))
        {
          try
          {
            Cert cert = Cert.importCert(value);
            X509Certificate x509Certificate = cert.getX509Certificate();
            PublicJsonWebKey publicJsonWebKey = PublicJsonWebKey.Factory.newPublicJwk(x509Certificate.getPublicKey());
            publicJsonWebKey.setCertificateChain(new X509Certificate[] { x509Certificate });
            publicJsonWebKey.setX509CertificateSha1Thumbprint(publicJsonWebKey.getX509CertificateSha1Thumbprint(true));
            return publicJsonWebKey;
          }
          catch (CertificateException e)
          {
            log.debug("Unable to parse certificate from " + name + " " + value + " : " + ExceptionUtil.toStringWithCauses(e));
            throw new ValidationException("Invalid Certificate in " + name + ": " + e.getMessage());
          }
        }
        
        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(value);
        if (!(jsonWebKey instanceof PublicJsonWebKey))
        {
          throw new ValidationException(name + " must be a public key (not '" + jsonWebKey.getKeyType() + "' key type).");
        }
        
        PublicJsonWebKey publicJsonWebKey = (PublicJsonWebKey)jsonWebKey;
        if (publicJsonWebKey.getPrivateKey() != null)
        {
          throw new ValidationException("The " + name + " should only contain the public component.");
        }
        return publicJsonWebKey;
      }
      catch (JoseException e)
      {
        log.debug("Unable to parse JWK from " + name + " " + value + " : " + ExceptionUtil.toStringWithCauses(e));
        throw new ValidationException("Invalid JWK in " + name + ": " + e.getMessage());
      }
    }
    return null;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\access\token\management\plugins\PublicJwkSupport.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */