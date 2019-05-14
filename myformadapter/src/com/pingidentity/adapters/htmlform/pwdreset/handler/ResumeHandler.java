package com.pingidentity.adapters.htmlform.pwdreset.handler;

import com.pingidentity.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.model.ResumeForm;
import com.pingidentity.adapters.htmlform.pwdreset.type.ResumeResult;
import com.pingidentity.adapters.htmlform.pwdreset.util.SessionStateUtil;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.service.AssertionReplayPreventionService;
import org.sourceid.saml20.state.StateMgmtFactory;
import org.sourceid.util.log.AttributeMap;




public class ResumeHandler
  extends BaseHandler
{
  private static Log logger = LogFactory.getLog(ResumeHandler.class);
  
  public ResumeHandler(PasswordManagementConfiguration configuration) {
    super(configuration);
  }
  

  public ResumeResult validateLink(ResumeForm resumeForm, HttpServletRequest request, HttpServletResponse response, Map<String, AttributeValue> attrs)
  {
    if ((resumeForm.getReferenceId() == null) || (resumeForm.getReferenceId().isEmpty())) {
      logger.debug("No Reference Id found in the form data");
      return ResumeResult.NoReferenceId;
    }
    
    if ((attrs == null) || (attrs.isEmpty()))
    {
      logger.debug("No attributes found for reference id " + resumeForm.getReferenceId());
      return ResumeResult.InvalidLink;
    }
    

    AttributeMap refAttributes = new AttributeMap(attrs);
    
    if (isReplayed(((AttributeValue)attrs.get("prCodeMapCode")).getValue()))
    {
      logger.debug("The reference id has already been used for a successful password reset and cannot be re-used " + resumeForm.getReferenceId());
      return ResumeResult.LinkExpired;
    }
    

    AttributeMap codeAttrMap = new AttributeMap();
    codeAttrMap.put("prCodeMapCode", refAttributes.getSingleValue("prCodeMapCode"));
    codeAttrMap.put("prExpTime", refAttributes.getSingleValue("prExpTime"));
    
    this.sessionUtil.add("prCodeMap", codeAttrMap, request, response);
    this.sessionUtil.add("prUsername", refAttributes.getSingleValue("prUsername"), request, response);
    this.sessionUtil.add("adapterId", refAttributes.getSingleValue("adapterId"), request, response);
    this.sessionUtil.add("pcvId", refAttributes.getSingleValue("pcvId"), request, response);
    this.sessionUtil.add("prEnableRememberUsername", refAttributes.getSingleValue("prEnableRememberUsername"), request, response);
    

    return ResumeResult.Success;
  }
  





  private boolean isReplayed(String code)
  {
    AssertionReplayPreventionService replaySvc = StateMgmtFactory.getBearerAssertionReplayPreventionSvc();
    return replaySvc.containsId(code);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\handler\ResumeHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */