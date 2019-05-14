package com.pingidentity.pf.access.token.management.plugins;

import com.pingidentity.configservice.Reloadable;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.http.Get;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithm;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.SimpleJwkFilter;
import org.jose4j.lang.JoseException;
import org.sourceid.common.ExceptionUtil;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.domain.mgmt.TrustedCAsManager;



public class RemoteJwksSupport
  implements Reloadable
{
  private final Log log = LogFactory.getLog(getClass());
  
  private final HttpsJwks httpsJwks;
  private final long defaultCacheDurationSeconds;
  private PublicJsonWebKey lastKnownGoodJwk;
  private long useLastKnownGoodJwkUntil;
  
  public RemoteJwksSupport(String location, long defaultCacheDurationMins)
  {
    this.defaultCacheDurationSeconds = (defaultCacheDurationMins * 60L);
    
    this.httpsJwks = new HttpsJwks(location);
    this.httpsJwks.setSimpleHttpGet(getGet());
    this.httpsJwks.setDefaultCacheDuration(this.defaultCacheDurationSeconds);
    
    MgmtFactory.getTrustedCAsManager().registerForReloadEvents(this);
  }
  
  public PublicJsonWebKey getEncryptionKeyFor(JsonWebEncryption jwe)
  {
    long now = System.currentTimeMillis();
    if (now < this.useLastKnownGoodJwkUntil)
    {
      if (this.lastKnownGoodJwk != null)
      {
        return this.lastKnownGoodJwk;
      }
    }
    


    try
    {
      List<JsonWebKey> jsonWebKeys = this.httpsJwks.getJsonWebKeys();
      
      SimpleJwkFilter filter = new SimpleJwkFilter();
      filter.setKty(jwe.getAlgorithm().getKeyType());
      filter.setUse("enc", false);
      filter.setAlg(jwe.getAlgorithmHeaderValue(), false);
      List<JsonWebKey> filtered = filter.filter(jsonWebKeys);
      
      if (filtered.isEmpty())
      {
        filter.setAlg(jwe.getAlgorithmHeaderValue(), true);
        filtered = filter.filter(jsonWebKeys);
        
        if (filtered.isEmpty())
        {
          filter.setUse("enc", true);
          filtered = filter.filter(jsonWebKeys);
        }
      }
      
      if (filtered.isEmpty())
      {

        throw new JoseException("Unable to find suitable encryption key for " + jwe.getAlgorithmHeaderValue() + " in JWKs from " + this.httpsJwks.getLocation() + " " + jsonWebKeys);
      }
      
      PublicJsonWebKey encryptionJwk = (PublicJsonWebKey)filtered.iterator().next();
      this.lastKnownGoodJwk = encryptionJwk;
    }
    catch (Exception e)
    {
      if (this.lastKnownGoodJwk != null)
      {
        PublicJsonWebKey encryptionJwk = this.lastKnownGoodJwk;
        this.useLastKnownGoodJwkUntil = (now + this.defaultCacheDurationSeconds * 1000L);
        this.log.warn("Will continue using the previous encryption key for a while (retry again after " + new Date(this.useLastKnownGoodJwkUntil) + ") due to a problem getting encryption key from JWKS URL " + this.httpsJwks
        
          .getLocation() + ": " + ExceptionUtil.toStringWithCauses(e));
      }
      else
      {
        throw new RuntimeException("Problem getting encryption key from JWKS URL " + this.httpsJwks.getLocation(), e);
      }
    }
    PublicJsonWebKey encryptionJwk;
    return encryptionJwk;
  }
  
  private Get getGet()
  {
    Get get = new Get();
    TrustedCAsManager trustedCAsManager = MgmtFactory.getTrustedCAsManager();
    Set<TrustAnchor> allTrustAnchors = trustedCAsManager.getAllTrustAnchors();
    Collection<X509Certificate> trustedCertificates = new ArrayList();
    for (TrustAnchor ta : allTrustAnchors)
    {
      trustedCertificates.add(ta.getTrustedCert());
    }
    get.setTrustedCertificates(trustedCertificates);
    return get;
  }
  

  public void reload()
  {
    this.httpsJwks.setSimpleHttpGet(getGet());
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\access\token\management\plugins\RemoteJwksSupport.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */