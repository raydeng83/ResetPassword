package com.efx.pingfed.adapters.htmlform.pwdreset.servlet;

import com.efx.pingfed.adapters.htmlform.idp.ForgotPasswordHtmlFormIdpAuthnAdapter;
import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.efx.pingfed.adapters.htmlform.pwdreset.handler.SelectMethodHandler;
import com.efx.pingfed.adapters.htmlform.pwdreset.ldap.LdapOperation;
import com.efx.pingfed.adapters.htmlform.pwdreset.ldap.LdapUser;
import com.efx.pingfed.adapters.htmlform.pwdreset.type.IdentifyResult;
import com.pingidentity.adapters.htmlform.pwdreset.model.IdentifyForm;
import com.pingidentity.adapters.htmlform.pwdreset.util.PwdResetAuditLogger;
import com.pingidentity.adapters.htmlform.pwdreset.common.PasswordResetConfigHelper;
import com.efx.pingfed.adapters.htmlform.pwdreset.util.UrlUtil;
import com.pingidentity.captcha.CaptchaServerSideValidator;
import com.pingidentity.captcha.CaptchaValidationError;
import com.pingidentity.common.util.CrossSiteRequestForgeryHelper;
import com.pingidentity.common.util.EscapeUtils;
import com.pingidentity.sdk.password.ResettablePasswordCredential;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.sourceid.config.GlobalRegistry;
import org.sourceid.oauth20.handlers.HandlerUtil;
import org.sourceid.saml20.domain.mgmt.InvalidRedirectValidationException;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.domain.mgmt.TargetResourceValidationMgr;
import org.sourceid.util.log.AttributeMap;
import org.sourceid.websso.servlet.reqparam.InvalidRequestParameterException;
import org.sourceid.websso.profiles.ProcessRuntimeException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

public class SelectMethodServlet extends AbstractPasswordResetServlet
{
    private static Log logger = LogFactory.getLog(SelectMethodServlet.class);
    private TargetResourceValidationMgr redirectValidationMgr = (TargetResourceValidationMgr) GlobalRegistry.getService(TargetResourceValidationMgr.class);

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException
    {
        logger.info("GET Request to /ext/pwdreset/SelectMethod");

        UrlUtil urlUtil = new UrlUtil(request);
        PwdResetAuditLogger.init("PWD_RESET_REQUEST", request, response);
        Map<String, Object> defaultParams = getDefaultParams(request);

        if ((!validStage("stage1Start", request, response))) {
            PwdResetAuditLogger.logFailure("Invalid state (unauthorized method)");
            redirect(response, urlUtil.buildErrorUrl("forgot-password-error.invalidState"));
            return;
        }

        String cSRFToken = CrossSiteRequestForgeryHelper.getCSRFToken(request, response);
        defaultParams.put("cSRFToken", cSRFToken);

        String username = request.getParameter("username");

        logger.info("Username got from request parameter is " + username);

        defaultParams.put("username", EscapeUtils.escape(username));

        // String requestAdapterId = request.getParameter("AdapterId");
        String requestAdapterId = (String) this.sessionUtil.get("adapterId", request, response);

        logger.info("AdapterId got from request parameter is " + requestAdapterId);


        PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);

        AttributeMap userAttributes = null;
        String selectedPcvId = null;

        for (String pcvId : configuration.getPcvIds())
        {
            try
            {
                LdapUser ldapUser = LdapOperation.getInstance().searchUser(username);
                logger.info("User found in ldap is " + ldapUser);

                if ( ldapUser != null) {
                    selectedPcvId = pcvId;
                    if(ldapUser.getEmailAddress() != null) {
                        defaultParams.put("hasOTP", true);
                    }
                    if(ldapUser.getMobile() != null) {
                        defaultParams.put("hasSMS", true);
                    }
                    break;
                }

//                userAttributes = getAttributes(username, pcvId);
//
//                if (userAttributes != null)
//                {
//                    selectedPcvId = pcvId;
//                    if(userAttributes.getSingleValue("mail") != null && !userAttributes.getSingleValue("mail").isEmpty()) {
//                        defaultParams.put("hasOTP", true);
//                    }
//
//                    if(userAttributes.getSingleValue("mobile") != null && !userAttributes.getSingleValue("mobile").isEmpty()) {
//                        defaultParams.put("hasSMS", true);
//                    }
//                    break;
//                }
            }
            catch (Exception e)
            {
                logger.error("Error retrieving user attributes. " + e.getMessage());
                logger.debug(e);
            }
        }

        render(request, response, defaultParams);
    }

    private IdentifyForm parseRequest(HttpServletRequest request, HttpServletResponse response)
            throws InvalidRequestParameterException
    {
        IdentifyForm identifyForm = new IdentifyForm(this.sessionUtil, request, response);

        String username = request.getParameter("username");
        String rawTargetResource = request.getParameter("savedReferrer");

        identifyForm.setUsername(username);
        if ((StringUtils.isNotEmpty(rawTargetResource)) && (!"$returnInfo".equals(rawTargetResource))) {
            try
            {
                boolean hasUpnavigation = HandlerUtil.pathContainsUpNavigation(new URI(rawTargetResource));

                boolean setTargetResource = true;
                if ((!fromHtmlFormAdapter(rawTargetResource)) && (redirectValidationMgr.isEnableValidationTargetResourceSLOAndOther())) {
                    try
                    {
                        redirectValidationMgr.validateTargetResourceSloAndOther(rawTargetResource, null);
                    }
                    catch (InvalidRedirectValidationException ex)
                    {
                        logger.warn(String.format("Ignoring request parameter TargetResource '%s' as it does not pass TargetResource validation.", new Object[] { rawTargetResource }));
                        setTargetResource = false;
                    }
                }
                if (hasUpnavigation)
                {
                    String message = "The value '" + rawTargetResource + "' for the request parameter '" + "savedReferrer" + "' contains up-navigation and is disallowed.";
                    throw new InvalidRequestParameterException(message);
                }
                if (setTargetResource) {
                    identifyForm.setTargetResource(rawTargetResource);
                }
            }
            catch (URISyntaxException e)
            {
                String message = "The request parameter 'savedReferrer' has an invalid URL value '" + rawTargetResource + "'.";
                throw new InvalidRequestParameterException(message);
            }
        }
        if (request.getParameter("Resume") != null)
        {
            boolean isClicked = request.getParameter("Resume").equals("clicked");
            identifyForm.setSubmit(isClicked);
        }
        return identifyForm;
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException
    {
        logger.debug("POST Request to /ext/pwdreset/SelectMethod");

        String recoveryOption = request.getParameter("recoveryOption");
        logger.info("The selected recovery option is ... " + recoveryOption);

        UrlUtil urlUtil = new UrlUtil(request);
        PwdResetAuditLogger.init("PWD_RESET_REQUEST", request, response);
        Map<String, Object> defaultParams = getDefaultParams(request);

        String cSRFToken = validateCSRFToken(request, response);
        if ((cSRFToken == null) || (!validStage("stage1Start", request, response)))
        {
            PwdResetAuditLogger.logFailure("Invalid state (unauthorized method)");
            redirect(response, urlUtil.buildErrorUrl("forgot-password-error.invalidState"));
            return;
        }
        defaultParams.put("cSRFToken", cSRFToken);

        IdentifyForm form = null;
        IdentifyResult validationResult = null;

        // String adapterId = getAdapterId(request, response);
        String adapterId = "ForgotPasswordAdapter";
        PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);

        if(recoveryOption.equals("OTP")) {
            configuration.setResetType("OTP");
        } else if (recoveryOption.equals("SMS")) {
            configuration.setResetType("SMS");

        } else if (recoveryOption.equals("PingID")) {
            configuration.setResetType("PingID");
        }

        try
        {
            form = parseRequest(request, response);
            String username = form.getUsername();
            logger.info("Posted username is " + username);

            if ((form.isSubmit()) && (configuration.isEnableCaptcha()))
            {
                CaptchaServerSideValidator captchaServerSideValidator = new CaptchaServerSideValidator(request, MgmtFactory.getCaptchaManager().getCaptchaSettings().getSecretKey());
                boolean isValid = captchaServerSideValidator.validateRecaptcha();
                if (!isValid)
                {
                    logger.debug("Login failed: reCAPTCHA validation failure.");
                    if (captchaServerSideValidator.hasErrors()) {
                        for (CaptchaValidationError captchaValidationError : captchaServerSideValidator.getErrors()) {
                            logger.error("Login failed due to: " + captchaValidationError.getErrorId() + " - " + captchaValidationError.getMessage());
                        }
                    }
                    validationResult = IdentifyResult.Error;
                }
            }
            if (validationResult == null)
            {
                PwdResetAuditLogger.setUserName(form.getUsername());
                SelectMethodHandler handler = new SelectMethodHandler(configuration);
                validationResult = handler.validateUsername(form, request, response);
                // validationResult = IdentifyResult.CodeSent;

            }
            setStage("stage1End", request, response);
            this.sessionUtil.add("adapterId", configuration.getAdapterId(), request, response);

        }
        catch (InvalidRequestParameterException e)
        {
            logger.error(e.getMessage());
            validationResult = IdentifyResult.Error;
        }
        catch (JSONException e)
        {
            logger.error(e.getMessage());
            validationResult = IdentifyResult.Error;
        }
        catch (IOException e)
        {
            logger.error(e.getMessage());
            validationResult = IdentifyResult.Error;
        }
        auditRequestResult(validationResult);

        switch (validationResult)
        {
            case PingID:
                redirect(response, urlUtil.buildPingIdUrl());
                break;
            case UserNotFound:
            case NoEmailAddress:
                if ("PingID".equals(configuration.getResetType())) {
                    redirect(response, urlUtil.buildErrorUrl("forgot-password-error.notEnrolled"));
                } else if ("OTL".equals(configuration.getResetType())) {
                    redirect(response, urlUtil.buildSuccessUrl("forgot-password-success.onetimeLinkSent"));
                }
                break;
            case EmailUnverifiedCodeNotSent:
            case CodeSent:
            case SmsSent:
            case SmsNotSent:
            case NoMobilePhone:

                redirect(response, urlUtil.buildSecurityCodeUrl());
                break;
            case EmailUnverifiedLinkNotSent:
            case LinkSent:
                redirect(response, urlUtil.buildSuccessUrl("forgot-password-success.onetimeLinkSent"));
                saveSessionForOTLContinue(request, response, form);

                break;
            case Error:
                redirect(response, urlUtil.buildErrorUrl(""));
                break;
            case RecoverUsername:
                String baseUrl = MgmtFactory.getLocalSettingsManager().getLocalSettings().getBaseUrl();
                redirect(response, ForgotPasswordHtmlFormIdpAuthnAdapter.getRecoverUsernameUrl(baseUrl, configuration.getAdapterId(), form.getTargetResource()), false);
                break;
            case Cancel:
                clearState(request, response);
                redirect(response, urlUtil.buildCancelUrl(form.getTargetResource()));
                break;
            case NoUsername:
                defaultParams.put("errorMessageKey", "forgot-password.noUsername");
                if (form.getTargetResource() != null) {
                    defaultParams.put("returnInfo", EscapeUtils.escape(form.getTargetResource()));
                }
                render(request, response, defaultParams);
        }
    }

    private static void auditRequestResult(IdentifyResult validationResult)
    {
        switch (validationResult)
        {
            case Cancel:
            case NoUsername:
                break;
            case SmsNotSent:
            case Error:
                PwdResetAuditLogger.logFailure("System error (see server log)");
                break;
            case UserNotFound:
                PwdResetAuditLogger.logFailure("User not found");
                break;
            case NoEmailAddress:
                PwdResetAuditLogger.logFailure("Email address not found");
                break;
            case NoMobilePhone:
                PwdResetAuditLogger.logFailure("Phone number for SMS not found");
                break;
            case EmailUnverifiedCodeNotSent:
            case EmailUnverifiedLinkNotSent:
                PwdResetAuditLogger.logFailure("User found but email address not verified.");
                break;
            case PingID:
            case CodeSent:
            case SmsSent:
            case LinkSent:
                PwdResetAuditLogger.log();
                break;
        }
    }

    private void saveSessionForOTLContinue(HttpServletRequest request, HttpServletResponse response, IdentifyForm form)
    {
        this.sessionUtil.add("prUsername", form.getUsername(), request, response);
        String requestAdapterId = request.getParameter("AdapterId");
        if (requestAdapterId == null)
        {
            requestAdapterId = request.getParameter("adapterId");
        }
        this.sessionUtil.add("adapterId", requestAdapterId, request, response);
        this.sessionUtil.add("prReferrer", form.getTargetResource(), request, response);
    }

    protected PasswordManagementConfiguration getPasswordManagementConfiguration(String adapterId)

    {
        return super.getPasswordManagementConfiguration(adapterId);

    }

    private void render(HttpServletRequest request, HttpServletResponse response, Map<String, Object> params)
    {
        PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);

        params.put("url", request.getContextPath() + "/");
        params.put("usernameField", "username");
        params.put("returnInfoField", "savedReferrer");
        params.put("ok", "Resume");
        params.put("cancel", "Cancel");
        params.put("usernameRecovery", "pf.usernamerecovery");
        params.put("supportsUsernameRecovery", Boolean.valueOf(getRecoverUsernameConfiguration(request, response).isEnableUsernameRecovery()));
        params.put("captchaEnabled", Boolean.valueOf(configuration.isEnableCaptcha()));
        if (configuration.isEnableCaptcha())
        {
            params.put("siteKey", MgmtFactory.getCaptchaManager().getCaptchaSettings().getSiteKey());
        }


        if (!params.containsKey("savedUsername")) {
            params.put("savedUsername", "");
        }


        setStage("stage1Start", request, response);
        try
        {
            com.pingidentity.sdk.template.TemplateRendererUtil.render(request, response, configuration.getSelectMethodTemplate(), params);
        }
        catch (Exception ex)
        {
            logger.error("Error on Request to /ext/pwdreset/Identify", ex);
            throw new ProcessRuntimeException(ex);
        }
    }

    private AttributeMap getAttributes(String username, String pcvId) {
        try {
            ResettablePasswordCredential pcv = (ResettablePasswordCredential)MgmtFactory.getCredentialValidatorManager().getValidator(pcvId);
            return pcv.findUser(username);

        }
        catch (Exception e)
        {
            if ((e.getMessage() != null) && (e.getMessage().contains("User not found")))
            {
                logger.debug(e.getMessage());
            }
            else
            {
                logger.error("Error retrieving user attributes. " + e.getMessage());
                logger.debug(e);
            }
        }
        return null;
    }

    private com.pingidentity.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration getOriginalPasswordManagementConfiguration(HttpServletRequest request, HttpServletResponse response)
    {
        String adapterId = getAdapterId(request, response);
        return com.pingidentity.adapters.htmlform.pwdreset.common.PasswordResetConfigHelper.get(adapterId);
    }


}
