package com.pingidentity.adapters.htmlform.pwdreset.util;

import com.pingidentity.common.util.LogGuard;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.xmlbeans.impl.util.HexBin;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.service.ArtifactPersistenceService;
import org.sourceid.saml20.service.ArtifactPersistenceService.Handle;
import org.sourceid.saml20.service.ArtifactPersistenceService.Message;
import org.sourceid.saml20.service.ArtifactPersistenceServiceException;
import org.sourceid.saml20.state.StateMgmtFactory;

public class ArtifactPersistenceUtil
{
  private static final Log logger = org.apache.commons.logging.LogFactory.getLog(ArtifactPersistenceUtil.class);
  
  protected ArtifactPersistenceService persistenceService;
  private static final int REF_LENGTH = 30;
  private static final int REF_TIMEOUT = 180;
  
  public ArtifactPersistenceUtil()
  {
    this.persistenceService = StateMgmtFactory.getArtifactPersistenceService();
  }
  






  public String storeAttributes(Map<String, AttributeValue> attributes)
  {
    return storeAttributes(attributes, 180);
  }
  







  public String storeAttributes(Map<String, AttributeValue> attributes, int timeout)
  {
    ArtifactPersistenceService.Message message = new ArtifactPersistenceService.Message(attributes);
    message.setMessageHandleLength(30);
    
    String ref = null;
    try {
      ArtifactPersistenceService.Handle handle = this.persistenceService.saveArtifact(message, timeout);
      byte[] messageHandleBytes = handle.getMessageHandle();
      ref = HexBin.bytesToString(messageHandleBytes);
      
      if (logger.isDebugEnabled()) {
        StringBuilder sb = new StringBuilder().append("Attributes ").append(org.sourceid.util.log.AttributeMap.toString(attributes));
        sb.append("  stored for reference ").append(ref);
        logger.debug(sb);
      }
    }
    catch (ArtifactPersistenceServiceException e) {
      logger.error("Unable to save attributes for reference " + ref, e);
    }
    return ref;
  }
  








  public Map<String, AttributeValue> retrieveAttributes(String ref)
  {
    Map<String, AttributeValue> attributes = new HashMap();
    
    if (ref != null)
    {
      byte[] bytes = HexBin.stringToBytes(ref);
      
      if (bytes != null)
      {
        try
        {
          ArtifactPersistenceService.Message message = this.persistenceService.retrieveAndRemoveArtifact(bytes);
          if (message != null)
          {
            attributes = (Map)message.getMsg();
          }
        }
        catch (ArtifactPersistenceServiceException e)
        {
          logger.error("Unable to retrieve attributes for ref " + LogGuard.encode(ref));
          if (logger.isDebugEnabled())
          {
            logger.debug("Unable to retrieve attributes for ref " + ref, e);
          }
        }
      }
    }
    
    return attributes;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdrese\\util\ArtifactPersistenceUtil.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */