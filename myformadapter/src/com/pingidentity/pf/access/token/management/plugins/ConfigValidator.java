package com.pingidentity.pf.access.token.management.plugins;

import com.pingidentity.common.util.PropertyInfo;
import com.pingidentity.common.util.PropertyInfo.HSM_MODE;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500PrivateCredential;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwa.AlgorithmFactory;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.jwe.ContentEncryptionAlgorithm;
import org.jose4j.jwe.KeyManagementAlgorithm;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignatureAlgorithm;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;
import org.sourceid.token.jwt.JWTKeyDerivationUtil;








public class ConfigValidator
  implements ConfigurationValidator
{
  private final Log log = LogFactory.getLog(getClass());
  private CertificateSupport certificateSupport;
  
  public ConfigValidator(CertificateSupport certificateSupport)
  {
    this.certificateSupport = certificateSupport;
  }
  
  public void validate(Configuration configuration)
    throws ValidationException
  {
    List<String> errorMessages = new LinkedList();
    AlgorithmFactoryFactory aff = AlgorithmFactoryFactory.getInstance();
    
    boolean symmetricJwe = false;
    
    try
    {
      String jweAlgoName = configuration.getFieldValue("JWE Algorithm");
      if (StringUtils.isNotBlank(jweAlgoName))
      {
        String encAlgName = configuration.getFieldValue("JWE Content Encryption Algorithm");
        
        if (StringUtils.isBlank(encAlgName))
        {
          errorMessages.add("Please select a JWE Content Encryption Algorithm (it's required when JWE Algorithm is used).");

        }
        else
        {
          AlgorithmFactory<ContentEncryptionAlgorithm> jweContentEncryptionAlgorithmFactory = aff.getJweContentEncryptionAlgorithmFactory();
          if (!jweContentEncryptionAlgorithmFactory.isAvailable(encAlgName))
          {
            errorMessages.add(getUnavailableMsg("JWE Content Encryption Algorithm", encAlgName));
          }
        }
        
        AlgorithmFactory<KeyManagementAlgorithm> jweKeyManagementAlgorithmFactory = aff.getJweKeyManagementAlgorithmFactory();
        if (!jweKeyManagementAlgorithmFactory.isAvailable(jweAlgoName))
        {
          errorMessages.add(getUnavailableMsg("JWE Algorithm", jweAlgoName));
        }
        else
        {
          KeyManagementAlgorithm jweAlgo = (KeyManagementAlgorithm)jweKeyManagementAlgorithmFactory.getAlgorithm(jweAlgoName);
          switch (jweAlgo.getKeyPersuasion())
          {
          case ASYMMETRIC: 
            Field keyField = configuration.getField("Asymmetric Encryption Key");
            PublicJsonWebKey publicJwk = PublicJwkSupport.getKey(keyField);
            boolean hasJwksUrl = StringUtils.isNotBlank(configuration.getFieldValue("Asymmetric Encryption JWKS URL"));
            boolean hasJwk = publicJwk != null;
            if ((hasJwk) && (hasJwksUrl))
            {
              errorMessages.add("When using asymmetric encryption, please specify either Asymmetric Encryption Key or Asymmetric Encryption JWKS URL but not both.");
            }
            else if (hasJwk)
            {
              try
              {
                PublicKey publicKey = publicJwk.getPublicKey();
                String keyAlg = publicKey.getAlgorithm();
                String algKeyAlg = jweAlgo.getKeyType();
                if (!StringUtils.equals(algKeyAlg, keyAlg))
                {
                  errorMessages.add("The type of key of the Asymmetric Encryption Key (" + keyAlg + ") does not match the type needed for the selected " + "JWE Algorithm" + " (" + algKeyAlg + ").");
                }
                

                jweAlgo.validateEncryptionKey(publicKey, null);
                boolean includeKid = configuration.getBooleanFieldValue("Include JWE Key ID Header Parameter");
                if ((includeKid) && (publicJwk.getKeyId() == null))
                {
                  errorMessages.add("Asymmetric Encryption Key needs to have a Key ID (kid) parameter in order to use Include JWE Key ID Header Parameter");
                }
                
                boolean includeX5t = configuration.getBooleanFieldValue("Include JWE X.509 Thumbprint Header Parameter");
                if ((includeX5t) && (publicJwk.getX509CertificateSha1Thumbprint(true) == null))
                {
                  errorMessages.add("Cannot use Include JWE X.509 Thumbprint Header Parameter unless Asymmetric Encryption Key is a JWK that has an X.509 Thumbprint (x5t) or certificate chain (x5c) or is itself a certificate.");
                }
                
              }
              catch (InvalidKeyException e)
              {
                errorMessages.add("Asymmetric Encryption Key is not valid for the selected JWE Algorithm: " + e.getMessage());
              }
              
            } else if (!hasJwksUrl)
            {
              errorMessages.add("Asymmetric Encryption Key or Asymmetric Encryption JWKS URL is required for the selected JWE Algorithm");
            }
            
            break;
          case SYMMETRIC: 
            symmetricJwe = true;
            String kid = checkNeededForAlgo(configuration, "Active Symmetric Encryption Key ID", errorMessages, "JWE Algorithm");
            checkSymmetricJweKeyLength(configuration, errorMessages, jweAlgoName, encAlgName, kid);
          }
          
        }
      }
      
      String jwsAlgoName = configuration.getFieldValue("JWS Algorithm");
      if (StringUtils.isBlank(jwsAlgoName))
      {
        if (!symmetricJwe)
        {
          errorMessages.add("Please provide integrity protection with a JWS Algorithm and/or a symmetric JWE Algorithm.");
        }
      }
      else
      {
        AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory = aff.getJwsAlgorithmFactory();
        if (!jwsAlgorithmFactory.isAvailable(jwsAlgoName))
        {
          errorMessages.add(getUnavailableMsg("JWS Algorithm", jwsAlgoName));
        }
        else
        {
          JsonWebSignatureAlgorithm jwsAlgo = (JsonWebSignatureAlgorithm)jwsAlgorithmFactory.getAlgorithm(jwsAlgoName);
          KeyPersuasion keyPersuasion = jwsAlgo.getKeyPersuasion();
          switch (keyPersuasion)
          {
          case ASYMMETRIC: 
            String kid = checkNeededForAlgo(configuration, "Active Signing Certificate Key ID", errorMessages, "JWS Algorithm");
            checkJwsKey(configuration, errorMessages, jwsAlgo, kid);
            break;
          case SYMMETRIC: 
            String kid = checkNeededForAlgo(configuration, "Active Symmetric Key ID", errorMessages, "JWS Algorithm");
            checkHmacKeyLength(configuration, errorMessages, jwsAlgoName, kid);
          }
          
        }
      }
    }
    catch (JoseException e)
    {
      this.log.error("Problem looking up algorithm for checking key type/requirements: " + e, e);
    }
    
    checkInterdependence(configuration, "JWKS Endpoint Path", "JWKS Endpoint Cache Duration", errorMessages);
    checkInterdependence(configuration, "Asymmetric Encryption JWKS URL", "Default JWKS URL Cache Duration", errorMessages);
    
    checkNotSame(configuration, "Client ID Claim Name", "Scope Claim Name", errorMessages);
    checkNotSame(configuration, "Client ID Claim Name", "Access Grant GUID Claim Name", errorMessages);
    checkNotSame(configuration, "Access Grant GUID Claim Name", "Scope Claim Name", errorMessages);
    
    checkUniqueKid(configuration.getTable("Symmetric Keys"), errorMessages);
    checkUniqueKid(configuration.getTable("Certificates"), errorMessages);
    
    if (!errorMessages.isEmpty())
    {
      throw new ValidationException(errorMessages);
    }
  }
  
  private void checkInterdependence(Configuration c, String ifName, String thenName, List<String> errorMessages)
  {
    if (StringUtils.isNotBlank(c.getFieldValue(ifName)))
    {
      if (StringUtils.isBlank(c.getFieldValue(thenName)))
      {
        errorMessages.add(thenName + " is required when utilizing " + ifName);
      }
    }
  }
  
  private void checkJwsKey(Configuration c, List<String> errorMessages, JsonWebSignatureAlgorithm jwsAlgo, String selectedKid)
  {
    Table certs = c.getTable("Certificates");
    List<Row> rows = certs.getRows();
    for (Row row : rows)
    {
      String kid = row.getFieldValue("Key ID");
      if (StringUtils.equals(selectedKid, kid))
      {
        String alias = row.getFieldValue("Certificate");
        X500PrivateCredential x500pc = this.certificateSupport.getDsigKeypair(alias);
        if (x500pc != null)
        {
          try
          {
            PrivateKey privateKey = x500pc.getPrivateKey();
            String keyAlg = privateKey.getAlgorithm();
            String algKeyAlg = jwsAlgo.getKeyType();
            if ((StringUtils.equals(algKeyAlg, keyAlg)) || (isNcipherEC(algKeyAlg, keyAlg)))
            {
              jwsAlgo.validateSigningKey(privateKey);
            }
            else
            {
              errorMessages.add("The type of key of the Active Signing Certificate Key ID (" + keyAlg + ") does not match the type needed for the selected " + "JWS Algorithm" + " (" + algKeyAlg + ").");
            }
            
          }
          catch (InvalidKeyException e)
          {
            errorMessages.add("Active Signing Certificate Key ID is not valid for the selected JWS Algorithm: " + e.getMessage());
          }
        }
      }
    }
  }
  


  private boolean isNcipherEC(String algKeyAlg, String keyAlg)
  {
    return (PropertyInfo.getHSMMode() == PropertyInfo.HSM_MODE.NCIPHER) && ("EC".equals(algKeyAlg)) && ("ECDSA".equals(keyAlg));
  }
  
  private String getUnavailableMsg(String which, String alg)
  {
    return "The selected " + which + " (" + alg + ") is not available due to the capabilities and configuration of the underlying JCE provider(s).";
  }
  
  private void checkSymmetricJweKeyLength(Configuration configuration, List<String> errorMessages, String jweAlgoName, String encAlgName, String kid)
  {
    Table table = configuration.getTable("Symmetric Keys");
    for (Row row : table.getRows())
    {
      if (StringUtils.equals(kid, row.getFieldValue("Key ID")))
      {
        int unknown = -1;
        int neededBitLength = unknown;
        String selectedAlgorithm = "selected ";
        if ("dir".equals(jweAlgoName))
        {
          selectedAlgorithm = selectedAlgorithm + "JWE content encryption algorithm";
          neededBitLength = JWTKeyDerivationUtil.getKeySize(encAlgName);
        }
        else
        {
          selectedAlgorithm = selectedAlgorithm + "JWE algorithm";
          switch (jweAlgoName)
          {
          case "A128KW": 
          case "A128GCMKW": 
            neededBitLength = 128;
            break;
          case "A192KW": 
          case "A192GCMKW": 
            neededBitLength = 192;
            break;
          case "A256KW": 
          case "A256GCMKW": 
            neededBitLength = 256;
          }
          
        }
        
        Key key = SymmetricKeySupport.getKey(row);
        int keyBitLen = key.getEncoded().length * 8;
        
        if ((neededBitLength != keyBitLen) && (neededBitLength != unknown))
        {
          errorMessages.add("Key ID '" + kid + "' is " + keyBitLen + " bits but keys used with the " + selectedAlgorithm + " need to be " + 
            SymmetricKeySupport.getExactBitsMessagePart(neededBitLength));
        }
      }
    }
  }
  
  private void checkHmacKeyLength(Configuration configuration, List<String> errorMessages, String jwsAlgoName, String kid)
  {
    Table table = configuration.getTable("Symmetric Keys");
    for (Row row : table.getRows())
    {
      if (StringUtils.equals(kid, row.getFieldValue("Key ID")))
      {
        try
        {
          Key key = SymmetricKeySupport.getKeyChecked(row);
          int minBits = Integer.parseInt(jwsAlgoName.substring("HS".length()));
          
          int keyBitLen = key.getEncoded().length * 8;
          if (keyBitLen < minBits)
          {
            errorMessages.add("Key ID '" + kid + "' is only " + keyBitLen + " bits but keys used with the selected JWS algorithm need to be" + 
              SymmetricKeySupport.getAtLeastBitsMessagePart(minBits));
          }
        }
        catch (ValidationException e)
        {
          errorMessages.add(e.getMessage());
        }
      }
    }
  }
  
  private void checkUniqueKid(Table table, List<String> errMsgs)
  {
    Set<String> kids = new HashSet();
    for (Row row : table.getRows())
    {
      String kid = row.getFieldValue("Key ID");
      if (!kids.add(kid))
      {
        errMsgs.add("Duplicate Key ID value '" + kid + "' - please ensure that all " + "Key ID" + " values are unique in " + table
          .getName());
      }
    }
  }
  

  private void checkNotSame(Configuration configuration, String name1, String name2, List<String> errMsgs)
  {
    String value1 = configuration.getFieldValue(name1);
    String value2 = configuration.getFieldValue(name2);
    if ((StringUtils.isNotBlank(value1)) && (StringUtils.equals(value1, value2)))
    {
      errMsgs.add(name1 + " and " + name2 + " need to have unique values.");
    }
  }
  
  private String checkNeededForAlgo(Configuration configuration, String name, List<String> errMsgs, String selectedName)
  {
    String keyId = configuration.getFieldValue(name);
    if (StringUtils.isBlank(keyId))
    {
      errMsgs.add(name + " is required for the selected " + selectedName);
    }
    return keyId;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\access\token\management\plugins\ConfigValidator.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */