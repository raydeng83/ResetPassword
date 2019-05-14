package com.pingidentity.pf.access.token.management.plugins;

import com.pingidentity.access.KeyAccessor;
import com.pingidentity.common.util.Base64URL;
import com.pingidentity.crypto.Cert;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500PrivateCredential;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.gui.AbstractSelectionFieldDescriptor.OptionValue;
import org.sourceid.saml20.adapter.gui.DsigKeypairFieldDescriptor;
import org.sourceid.saml20.adapter.gui.SelectFieldDescriptor;






public class CertificateSupport
{
  static final int MIN_RSA_KEY_LENGTH = 2048;
  private final Log log = LogFactory.getLog(getClass());
  
  private final Map<String, X500PrivateCredential> x500PrivateCredentialMap = new LinkedHashMap();
  
  void init()
  {
    Collection<X500PrivateCredential> x500s = new ArrayList();
    KeyAccessor keyAccessor = new KeyAccessor();
    DsigKeypairFieldDescriptor desc = new DsigKeypairFieldDescriptor("fake", "");
    for (AbstractSelectionFieldDescriptor.OptionValue option : desc.getOptionValues())
    {
      String alias = option.getValue();
      if (StringUtils.isNotBlank(alias))
      {
        x500s.add(keyAccessor.getDsigKeypair(alias));
      }
    }
    
    init(x500s);
  }
  
  void init(Collection<X500PrivateCredential> x500s)
  {
    this.x500PrivateCredentialMap.clear();
    for (X500PrivateCredential x500PrivateCredential : x500s)
    {
      if (meetsCritera(x500PrivateCredential))
      {
        String alias = x500PrivateCredential.getAlias();
        this.x500PrivateCredentialMap.put(alias, x500PrivateCredential);
      }
    }
  }
  

  boolean meetsCritera(X500PrivateCredential x500PrivateCredential)
  {
    PublicKey pubKey = x500PrivateCredential.getCertificate().getPublicKey();
    return ((pubKey instanceof ECPublicKey)) || (((pubKey instanceof RSAPublicKey)) && (((RSAPublicKey)pubKey).getModulus().bitLength() >= 2048));
  }
  
  private List<AbstractSelectionFieldDescriptor.OptionValue> getOptions()
  {
    List<AbstractSelectionFieldDescriptor.OptionValue> options = new LinkedList();
    options.add(SelectFieldDescriptor.SELECT_ONE);
    
    for (X500PrivateCredential x5 : getAvailableCredentials())
    {
      Cert cert = new Cert(x5.getAlias(), x5.getCertificate());
      String name = cert.getDescriptionForDisplay(35);
      String value = cert.getAlias();
      AbstractSelectionFieldDescriptor.OptionValue op = new AbstractSelectionFieldDescriptor.OptionValue(name, value);
      options.add(op);
    }
    
    return options;
  }
  
  public SelectFieldDescriptor getCertsDesc(String name, String desc)
  {
    return new FilteredKeypairFieldDescriptor(name, desc);
  }
  
  Collection<X500PrivateCredential> getAvailableCredentials()
  {
    return this.x500PrivateCredentialMap.values();
  }
  
  public X500PrivateCredential getDsigKeypair(String alias)
  {
    return (X500PrivateCredential)this.x500PrivateCredentialMap.get(alias);
  }
  
  public String calculateThumb(X509Certificate x509Certificate)
  {
    String hashAlgo = "SHA1";
    try
    {
      byte[] encoded = x509Certificate.getEncoded();
      MessageDigest digest = MessageDigest.getInstance(hashAlgo);
      byte[] thumbBytes = digest.digest(encoded);
      return Base64URL.encodeToString(thumbBytes);
    }
    catch (Exception e)
    {
      this.log.warn("Unexpected problem getting " + hashAlgo + " thumbprint for  " + x509Certificate, e); }
    return null;
  }
  
  class FilteredKeypairFieldDescriptor
    extends DsigKeypairFieldDescriptor
  {
    public FilteredKeypairFieldDescriptor(String name, String description)
    {
      super(description);
    }
    

    public List<AbstractSelectionFieldDescriptor.OptionValue> getOptionValues()
    {
      CertificateSupport.this.init();
      return CertificateSupport.this.getOptions();
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\access\token\management\plugins\CertificateSupport.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */