package com.efx.pingfed.adapters.htmlform.pwdreset.handler;

import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.model.SecurityCodeForm;
import com.pingidentity.adapters.htmlform.pwdreset.type.BaseResult;
import com.pingidentity.adapters.htmlform.pwdreset.type.SecurityCodeResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.util.log.AttributeMap;


public class SecurityCodeHandler
        extends BaseHandler
{
  private static Log logger = LogFactory.getLog(SecurityCodeHandler.class);

  public SecurityCodeHandler(PasswordManagementConfiguration configuration) {
    super(configuration);
  }

  public SecurityCodeResult validateCode(SecurityCodeForm securityCodeForm, HttpServletRequest request, HttpServletResponse response)
  {
    if (!securityCodeForm.isSubmit())
    {
      logger.debug("Form was not submitted");
      return SecurityCodeResult.Cancel;
    }

    if (StringUtils.isEmpty(securityCodeForm.getSecurityCode()))
    {
      logger.debug("No Security Code found in the form data");
      return SecurityCodeResult.NoCode;
    }

    AttributeMap userAttributes = getStoredCode(request, response);

    if (userAttributes != null)
    {
      return
              validateCode(securityCodeForm.getUsername(), securityCodeForm.getSecurityCode(), userAttributes, request, response).asSecurityCodeResult();
    }


    return SecurityCodeResult.InvalidCode;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\handler\SecurityCodeHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */