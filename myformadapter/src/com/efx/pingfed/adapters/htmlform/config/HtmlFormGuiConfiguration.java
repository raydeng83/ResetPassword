package com.efx.pingfed.adapters.htmlform.config;

import java.util.*;
import java.io.Serializable;

import org.sourceid.saml20.adapter.gui.*;
import org.sourceid.saml20.adapter.gui.validation.*;
import org.sourceid.saml20.adapter.gui.validation.impl.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.conf.*;

import com.efx.pingfed.adapters.htmlform.idp.ForgotPasswordHtmlFormIdpAuthnAdapter;

import org.sourceid.saml20.adapter.gui.localidentity.LocalIdentityProfileFieldDescriptor;
import org.sourceid.saml20.adapter.gui.event.PreRenderCallback;

public class HtmlFormGuiConfiguration {
  private static final Log log = LogFactory.getLog(HtmlFormGuiConfiguration.class);
  private static final int SESSION_IDLE_AND_MAX_MAX = 500000;
  private static final int SESSION_IDLE_AND_MAX_MIN = 1;
  public static final String FIELD_RETRIES = "Challenge Retries";
  public static final String DESC_RETRIES = "Max value of User Challenge Retries.";

  public static final String FIELD_LOGOUT_SUB_PATH = "Logout Path";
  public static final String DESC_LOGOUT_SUB_PATH = "Path on the PingFederate server to end a user's IdP session.  Must include the initial slash (example: /mylogoutpath). (Resulting URL will be http[s]://<pf_host>:<port>/ext/<Logout Path>). If specified, the path must be unique across HTML Form IdP Adapter instances, including child instances.";


  public static final String FIELD_LOGIN_TEMPLATE_NAME = "Login Template";
  public static final String DESC_LOGIN_TEMPLATE_NAME = "HTML template (in <pf_home>/server/default/conf/template) to render for login.  The default value is html.form.login.template.html.";
  public static final String DEFAULT_LOGIN_TEMPLATE_NAME = "html.form.login.template.html";

  public static final String FIELD_LOGOUT_REDIRECT_LOCATION = "Logout Redirect";
  public static final String DESC_LOGOUT_REDIRECT_LOCATION = "A fully qualified URL, usually at the SP, to which a user will be redirected after logout (applicable only when Logout Path is set above). When provided, this URL takes precedence over any Logout Template specified below.";



  public static final String FIELD_LOGOUT_TEMPLATE_NAME = "Logout Template";
  public static final String DESC_LOGOUT_TEMPLATE_NAME = "HTML template (in <pf_home>/server/default/conf/template) to render after logout (applicable only when Logout Path is set above and if Logout Redirect is not provided).  The default value is idp.logout.success.page.template.html.";
  public static final String DEFAULT_LOGOUT_TEMPLATE_NAME = "idp.logout.success.page.template.html";


  public static final String FIELD_ALLOW_PASSWORD_CHANGES = "Allow Password Changes";
  public static final String DESC_ALLOW_PASSWORD_CHANGES = "Allows users to change their password using this adapter.";
  public static final boolean DEFAULT_ALLOW_PASSWORD_CHANGES = true;

  public static final String FIELD_ENABLE_REMEMBER_USERNAME = "Enable 'Remember My Username'";
  public static final String DESC_ENABLE_REMEMBER_USERNAME = "Allows users to store their username as a cookie when authenticating with this adapter. Once stored, the username is pre-populated in the login form's username field on subsequent transactions.";
  public static final boolean DEFAULT_ENABLE_REMEMBER_USERNAME = false;

  public static final String FIELD_REMEMBER_USERNAME_LIFETIME = "'Remember My Username' Lifetime";
  public static final String DESC_REMEMBER_USERNAME_LIFETIME = "Number of days that the username is stored. The cookie lifetime is reset upon each successful login in which the 'Remember My Username' checkbox is selected. The default is 30.";
  public static final String DEFAULT_REMEMBER_USERNAME_LIFETIME = "30";

  public static final String FIELD_CHANGE_PASSWORD_TEMPLATE_NAME = "Change Password Template";
  public static final String DESC_CHANGE_PASSWORD_TEMPLATE_NAME = "HTML template (in <pf_home>/server/default/conf/template) to render for a user to change their password.  The default value is html.form.change.password.template.html.";
  public static final String DEFAULT_CHANGE_PASSWORD_TEMPLATE_NAME = "html.form.change.password.template.html";

  public static final String FIELD_CHANGE_PASSWORD_MESSAGE_TEMPLATE_NAME = "Change Password Message Template";
  public static final String DESC_CHANGE_PASSWORD_MESSAGE_TEMPLATE_NAME = "HTML template (in <pf_home>/server/default/conf/template) to render when a user is being redirected after successfully changing their password. If left blank, users are redirected without explanation.  The default value is html.form.message.template.html.";
  public static final String DEFAULT_CHANGE_PASSWORD_MESSAGE_TEMPLATE_NAME = "html.form.message.template.html";

  public static final String FIELD_LOGIN_CHALLENGE_TEMPLATE_NAME = "Login Challenge Template";
  public static final String DESC_LOGIN_CHALLENGE_TEMPLATE_NAME = "HTML template (in <pf_home>/server/default/conf/template) to render during a strong authentication as a second step. It is used to prompt the user to answer a challenge question after they login and the RADIUS Username Password Credential Validator is an example of where it could be used. The default value is html.form.login.challenge.template.html.";
  public static final String DEFAULT_LOGIN_CHALLENGE_TEMPLATE_NAME = "html.form.login.challenge.template.html";

  public static final String FIELD_PASSWORD_CHANGE_PWM = "Password Management System";
  public static final String DESC_PASSWORD_CHANGE_PWM = "A fully-qualified URL to your password management system where users can change their password. If left blank, password changes are handled by this adapter.";
  public static final String DEFAULT_PASSWORD_CHANGE_PWM = "";

  public static final String FIELD_PASSWORD_CHANGE_PWM_MESSAGE_TEMPLATE_NAME = "Password Management System Message Template";
  public static final String DESC_PASSWORD_CHANGE_PWM_MESSAGE_TEMPLATE_NAME = "HTML template (in <pf_home>/server/default/conf/template) to render when a user is being redirected to the password management system to change their password. If left blank, users are redirected without explanation.  The default value is html.form.message.template.html.";
  public static final String DEFAULT_PASSWORD_CHANGE_PWM_MESSAGE_TEMPLATE_NAME = "html.form.message.template.html";

  public static final String FIELD_PASSWORD_CHANGE_REAUTH_DELAY = "Post-Password Change Re-Authentication Delay";
  public static final String DESC_PASSWORD_CHANGE_REAUTH_DELAY = "Amount of time (milliseconds) to wait after a successful password change before automatically re-authenticating the user against the Password Credential Validator using the new password. The default (and minimum) value is 0. The maximum value is 60000.";
  public static final String DEFAULT_PASSWORD_CHANGE_REAUTH_DELAY = "0";

  public static final String FIELD_SESSION_MAX_TIMEOUT = "Session Max Timeout";
  public static final String DESC_SESSION_MAX_TIMEOUT = "Session Max Timeout (in minutes). Leave blank for indefinite sessions. Ignored if 'None' is selected for Session State.";
  public static final String DEFAULT_SESSION_MAX_TIMEOUT = "480";

  public static final String FIELD_ALLOW_USERNAME_EDITS = "Allow Username Edits During Chaining";
  public static final String DESC_ALLOW_USERNAME_EDIT = "Allow users to edit the pre-populated username field in the login form. Note that this is applicable when chained behind another adapter through a Composite Adapter or in some SSO protocols, such as OpenID Connect, that give the SP a way to provide a hint about what identifier an end-user might use to log in. The default value is false.";
  public static final boolean DEFAULT_ALLOW_USERNAME_EDITS = false;

  public static final String FIELD_EXPIRING_PASSWORD_WARNING_TEMPLATE_NAME = "Expiring Password Warning Template";
  public static final String DESC_EXPIRING_PASSWORD_WARNING_TEMPLATE_NAME = "HTML template (in <pf_home>/server/default/conf/template) to warn the user about approaching password expiry day. The default value is html.form.password.expiring.notification.template.html.";
  public static final String DEFAULT_PASSWORD_EXPIRY_TEMPLATE_NAME = "html.form.password.expiring.notification.template.html";

  public static final String FIELD_ENABLE_EXPIRING_PASSWORD_WARNING = "Show Password Expiring Warning";
  public static final String DESC_ENABLE_EXPIRING_PASSWORD_WARNING = "Show a warning message to the user on login about an approaching password expiration.";
  public static final boolean DEFAULT_ENABLE_EXPIRING_PASSWORD_WARNING = false;

  public static final String FIELD_EXPIRING_PASSWORD_WARNING_THRESHOLD = "Threshold for Expiring Password Warning";
  public static final String DESC_EXPIRING_PASSWORD_WARNING_THRESHOLD = "Threshold (in days) to start warning the user about approaching password expiry day. The default value is 7.";
  public static final String DEFAULT_PASSWORD_EXPIRING_WARNING_THRESHOLD = "7";

  public static final String FIELD_EXPIRING_PASSWORD_WARNING_DELAY = "Snooze Interval for Expiring Password Warning";
  public static final String DESC_EXPIRING_PASSWORD_WARNING_DELAY = "Amount of time (in hours) to wait after a expiring password warning before the next warning. The default value is 24.";
  public static final String DEFAULT_PASSWORD_EXPIRING_WARNING_DELAY = "24";

  public static final String FIELD_SESSION_TIMEOUT = "Session Timeout";
  public static final String DESC_SESSION_TIMEOUT = "Session Idle Timeout (in minutes). If left blank the timeout will be the Session Max Timeout. Ignored if 'None' is selected for Session State.";
  public static final String DEFAULT_SESSION_TIMEOUT = "60";


  public static final String ATTR_NAME_USERID = "username";
  public static final String ATTR_NAME_REQUESTEDACTION = "policy.action";
  public static final String MAX_CHALLENGE_DEFAULT = "3";

  public static final String SESSION_STATE = "Session State";
  public static final String DESC_SESSION_STATE = "Determines how state is maintained within one adapter or between different adapter instances.";
  public static final String OPTION_GLOBALLY = "Globally";
  public static final String OPTION_PER_ADAPTER_INSTANCE = "Per Adapter";
  public static final String OPTION_NONE = "None";

  public static final String FIELD_TRACK_AUTHN_TIME = "Track Authentication Time";
  public static final String DESC_TRACK_AUTHN_TIME = "Determines if the time each end user authenticated is tracked. This authentication instance information may be applied within some SSO protocols.";

  public static final String FIELD_ENABLE_CHANGE_PASSWORD_EMAIL_NOTIFICATION = "Change Password Email Notification";
  public static final String DESC_ENABLE_CHANGE_PASSWORD_EMAIL_NOTIFICATION = "Send users an email notification upon a password change. This feature relies on the underlying PCV returning 'mail' and 'givenName' attributes containing the user's first name and e-mail address. Additionally, mail settings should be configured within Server Settings.";
  public static final boolean DEFAULT_ENABLE_CHANGE_PASSWORD_EMAIL_NOTIFICATION = true;

  public static final String FIELD_CHANGE_PASSWORD_EMAIL_NOTIFICATION_TEMPLATE_NAME = "Change Password Email Template";
  public static final String DESC_CHANGE_PASSWORD_EMAIL_NOTIFICATION_TEMPLATE_NAME = "HTML email template (in <pf_home>/server/default/conf/template/mail-notifications) used to send a changing password email. The default value is message-template-end-user-password-change.html.";
  public static final String DEFAULT_CHANGE_PASSWORD_EMAIL_NOTIFICATION_TEMPLATE_NAME = "message-template-end-user-password-change.html";

  public static final String FIELD_RESET_PASSWORD_TEMPLATE_USERNAME_INPUT = "Password Reset Username Template";
  public static final String DESC_RESET_PASSWORD_TEMPLATE_USERNAME_INPUT = "HTML template (in <pf_home>/server/default/conf/template) rendered to prompt a user for their username during password reset. The default value is forgot-password.html.";
  public static final String DEFAULT_RESET_PASSWORD_TEMPLATE_USERNAME_INPUT = "forgot-password.html";

  public static final String FIELD_RESET_PASSWORD_TEMPLATE_CODE_INPUT = "Password Reset Code Template";
  public static final String DESC_RESET_PASSWORD_TEMPLATE_CODE_INPUT = "HTML template (in <pf_home>/server/default/conf/template) rendered to prompt a user for a code challenge during password reset. The default value is forgot-password-resume.html.";
  public static final String DEFAULT_RESET_PASSWORD_TEMPLATE_CODE_INPUT = "forgot-password-resume.html";

  public static final String FIELD_RESET_PASSWORD_TEMPLATE_CHANGE_INPUT = "Password Reset Template";
  public static final String DESC_RESET_PASSWORD_TEMPLATE_CHANGE_INPUT = "HTML template (in <pf_home>/server/default/conf/template) rendered to prompt a user to define their new password during password reset. The default value is forgot-password-change.html.";
  public static final String DEFAULT_RESET_PASSWORD_TEMPLATE_CHANGE_INPUT = "forgot-password-change.html";

  public static final String FIELD_RESET_PASSWORD_TEMPLATE_ERROR_INPUT = "Password Reset Error Template";
  public static final String DESC_RESET_PASSWORD_TEMPLATE_ERROR_INPUT = "HTML template (in <pf_home>/server/default/conf/template) to render when an error occurs during password reset. The default value is forgot-password-error.html.";
  public static final String DEFAULT_RESET_PASSWORD_TEMPLATE_ERROR_INPUT = "forgot-password-error.html";

  public static final String FIELD_RESET_PASSWORD_TEMPLATE_SUCCESS_INPUT = "Password Reset Success Template";
  public static final String DESC_RESET_PASSWORD_TEMPLATE_SUCCESS_INPUT = "HTML template (in <pf_home>/server/default/conf/template) rendered upon a successful password reset. The default value is forgot-password-success.html.";
  public static final String DEFAULT_RESET_PASSWORD_TEMPLATE_SUCCESS_INPUT = "forgot-password-success.html";

  public static final String FIELD_ACCOUNT_UNLOCK = "Account Unlock";
  public static final String DESC_ACCOUNT_UNLOCK = "Allows users with a locked account to unlock it using the self-service password reset type.";

  public static final String FIELD_ACCOUNT_UNLOCK_TEMPLATE = "Account Unlock Template";
  public static final String DESC_ACCOUNT_UNLOCK_TEMPLATE = "HTML template (in <pf_home>/server/default/conf/template) rendered when a user's account is sucessfully unlocked. The default value is account-unlock.html.";
  public static final String DEFAULT_ACCOUNT_UNLOCK_TEMPLATE = "account-unlock.html";

  public static final String FIELD_RESET_TYPE = "Password Reset Type";
  public static final String DESC_RESET_TYPE = "Select the method to use for self-service password reset. Depending on the selected method, additional settings are required to complete the configuration.";
  public static final String DEFAULT_RESET_TYPE = "NONE";

  public static final String FIELD_RESET_TYPE_NONE_NAME = "None";
  public static final String RESET_TYPE_NONE_VALUE = "NONE";

  public static final String FIELD_RESET_TYPE_OTL_NAME = "Email One-Time Link";
  public static final String RESET_TYPE_OTL_VALUE = "OTL";

  public static final String FIELD_RESET_TYPE_OTP_NAME = "Email One-Time Password";
  public static final String RESET_TYPE_OTP_VALUE = "OTP";

  public static final String RESET_TYPE_PINGID_NAME = "PingID";
  public static final String RESET_TYPE_PINGID_VALUE = "PingID";
  public static final String RESET_TYPE_SMS_NAME = "Text Message";
  public static final String RESET_TYPE_SMS_VALUE = "SMS";

  public static final String FIELD_CODE_NUMCHARS_INPUT = "OTP Length";
  public static final String DESC_CODE_NUMCHARS_INPUT = "For self-service password reset, the number of characters used in one-time passwords. Default: 8.";
  public static final String DEFAULT_CODE_NUMCHARS_INPUT = "8";

  public static final String FIELD_CODE_EXPIRATION_INPUT = "OTP Time to Live";
  public static final String DESC_CODE_EXPIRATION_INPUT = "For self-service password reset, the validity period (in minutes) for password reset tokens. Default: 10.";
  public static final String DEFAULT_CODE_EXPIRATION_INPUT = "10";

  public static final String FIELD_PINGID_PROPERTIES = "PingID Properties";
  public static final String DESC_PINGID_PROPERTIES = "For self-service password reset using PingID, upload your pingid.properties settings file from PingOne.";

  public static final String PROPERTY_BASE_64KEY = "use_base64_key";
  public static final String PROPERTY_TOKEN = "token";
  public static final String PROPERTY_ORG_ALIAS = "org_alias";
  public static final String PROPERTY_AUTHENTICATOR_URL = "authenticator_url";
  public static final String PROPERTY_ADMIN_URL = "admin_url";

  public static final String FIELD_ENABLE_USERNAME_RECOVERY = "Enable Username Recovery";
  public static final String DESC_ENABLE_USERNAME_RECOVERY = "Allow users to get their username from an email.";

  public static final String FIELD_REQUIRE_VERIFIED_EMAIL = "Require Verified Email";
  public static final String DESC_REQUIRE_VERIFIED_EMAIL = "The user’s email address has to be verified before a password reset, account unlock or username recovery email is sent.";

  public static final String FIELD_USERNAME_RECOVERY_TEMPLATE = "Username Recovery Template";
  public static final String DESC_USERNAME_RECOVERY_TEMPLATE = "HTML template (in <pf_home>/server/default/conf/template) rendered to prompt a user for their email address during username recovery. The default value is username.recovery.template.html.";
  public static final String DEFAULT_USERNAME_RECOVERY_TEMPLATE = "username.recovery.template.html";

  public static final String FIELD_USERNAME_RECOVERY_INFO_TEMPLATE = "Username Recovery Info Template";
  public static final String DESC_USERNAME_RECOVERY_INFO_TEMPLATE = "HTML template (in <pf_home>/server/default/conf/template) rendered to prompt a user to check their email for their recovered username. The default value is username.recovery.info.template.html.";
  public static final String DEFAULT_USERNAME_RECOVERY_INFO_TEMPLATE = "username.recovery.info.template.html";

  public static final String FIELD_USERNAME_RECOVERY_EMAIL_TEMPLATE = "Username Recovery Email Template";
  public static final String DESC_USERNAME_RECOVERY_EMAIL_TEMPLATE = "HTML email template (in <pf_home>/server/default/conf/template/mail-notifications) used to send a username recovery email. The default value is message-template-username-recovery.html.";
  public static final String DEFAULT_USERNAME_RECOVERY_EMAIL_TEMPLATE = "message-template-username-recovery.html";


  public static final String FIELD_ENABLE_CAPTCHA_AUTHENTICATION = "CAPTCHA for Authentication";
  public static final String DESC_ENABLE_CAPTCHA_AUTHENTICATION = "CAPTCHA can be enabled for the login form to prevent automated attacks.";
  public static final boolean DEFAULT_ENABLE_CAPTCHA_AUTHENTICATION = false;

  public static final String FIELD_ENABLE_CAPTCHA_USERNAME_RECOVERY = "CAPTCHA for Username recovery";
  public static final String DESC_ENABLE_CAPTCHA_USERNAME_RECOVERY = "CAPTCHA can be enabled for username recovery features to prevent automated attacks.";
  public static final boolean DEFAULT_ENABLE_CAPTCHA_USERNAME_RECOVERY = false;

  public static final String FIELD_ENABLE_CAPTCHA_PASS_RESET_ACCOUNT_UNLOCK = "CAPTCHA for Password Reset";
  public static final String DESC_ENABLE_CAPTCHA_PASS_RESET_ACCOUNT_UNLOCK = "CAPTCHA can be enabled for password reset and account unlock features to prevent automated attacks.";
  public static final boolean DEFAULT_ENABLE_CAPTCHA_PASS_RESET_ACCOUNT_UNLOCK = false;

  public static final String FIELD_ENABLE_CAPTCHA_PASSWORD_CHANGE = "CAPTCHA for Password change";
  public static final String DESC_ENABLE_CAPTCHA_PASSWORD_CHANGE = "CAPTCHA can be enabled for the password change form to prevent automated attacks.";
  public static final boolean DEFAULT_ENABLE_CAPTCHA_PASSWORD_CHANGE = false;

  private static final String FIELD_CHANGE_PASSWORD_ENDPOINT = "Change Password Endpoint";
  private static final String CHANGE_PASSWORD_ENDPOINT = "${baseUrl}/ext/pwdchange/Identify?AdapterId=${pluginId}";

  private static final String FIELD_PASSWORD_RESET_ENDPOINT = "Password Reset Endpoint";
  private static final String PASSWORD_RESET_ENDPOINT = "${baseUrl}/ext/pwdreset/Identify?AdapterId=${pluginId}";
  public AdapterConfigurationGuiDescriptor getGuiDescriptor()
  {

    log.info("....getGUIDescriptor");
    AdapterConfigurationGuiDescriptor guiDescriptor = new AdapterConfigurationGuiDescriptor();

    TableDescriptor pcvTable = new TableDescriptor("Credential Validators", "A list of Password Credential Validators to be used for authentication.");


    guiDescriptor.addTable(pcvTable);
    PasswordCredentialValidatorFieldDescriptor pcvField = new PasswordCredentialValidatorFieldDescriptor("Password Credential Validator Instance", "");


    pcvField.addValidator(new RequiredFieldValidator());
    pcvTable.addRowField(pcvField);
    pcvTable.addValidator(new PcvRowValidator());

    TextFieldDescriptor retries = new TextFieldDescriptor(FIELD_RETRIES, DESC_RETRIES);
    retries.addValidator(new RequiredFieldValidator());
    retries.addValidator(new IntegerValidator(1, 100));
    retries.setDefaultValue("3");
    guiDescriptor.addField(retries);

    String[] options = { OPTION_GLOBALLY, OPTION_PER_ADAPTER_INSTANCE, OPTION_NONE };
    RadioGroupFieldDescriptor sessionState = new RadioGroupFieldDescriptor(SESSION_STATE, DESC_SESSION_STATE, options);

    sessionState.setDefaultValue(OPTION_PER_ADAPTER_INSTANCE);

    guiDescriptor.addField(sessionState);

    TextFieldDescriptor sessionTimeout = new TextFieldDescriptor(FIELD_SESSION_TIMEOUT, DESC_SESSION_TIMEOUT);
    sessionTimeout.setDefaultValue(DEFAULT_SESSION_TIMEOUT);
    sessionTimeout.addValidator(new IntegerValidator(SESSION_IDLE_AND_MAX_MIN, SESSION_IDLE_AND_MAX_MAX), true);
    guiDescriptor.addField(sessionTimeout);

    TextFieldDescriptor sessionMaxTimeout = new TextFieldDescriptor(FIELD_SESSION_MAX_TIMEOUT, "Session Max Timeout (in minutes). Leave blank for indefinite sessions. Ignored if 'None' is selected for Session State.");
    sessionMaxTimeout.setDefaultValue(DEFAULT_SESSION_MAX_TIMEOUT);
    sessionMaxTimeout.addValidator(new IntegerValidator(SESSION_IDLE_AND_MAX_MIN, SESSION_IDLE_AND_MAX_MAX), true);
    guiDescriptor.addField(sessionMaxTimeout);

    TextFieldDescriptor loginTemplateName = new TextFieldDescriptor(FIELD_LOGIN_TEMPLATE_NAME, DESC_LOGIN_TEMPLATE_NAME);

    loginTemplateName.addValidator(new RequiredFieldValidator());
    loginTemplateName.setDefaultValue(DEFAULT_LOGIN_TEMPLATE_NAME);
    guiDescriptor.addAdvancedField(loginTemplateName);

    TextFieldDescriptor logoutSubPath = new TextFieldDescriptor(FIELD_LOGOUT_SUB_PATH, DESC_LOGOUT_SUB_PATH);
    logoutSubPath.setDefaultValue(null);
    logoutSubPath.addValidator(new com.pingidentity.adapters.htmlform.validators.SubPathValidator(), true);
    guiDescriptor.addAdvancedField(logoutSubPath);

    TextFieldDescriptor logoutRedirectLocation = new TextFieldDescriptor(FIELD_LOGOUT_REDIRECT_LOCATION, DESC_LOGOUT_REDIRECT_LOCATION);

    logoutRedirectLocation.setDefaultValue(null);
    logoutRedirectLocation.addValidator(new URLValidator(true), true);
    guiDescriptor.addAdvancedField(logoutRedirectLocation);

    TextFieldDescriptor logoutTemplateName = new TextFieldDescriptor(FIELD_LOGOUT_TEMPLATE_NAME, DESC_LOGOUT_TEMPLATE_NAME);

    logoutTemplateName.setDefaultValue(DEFAULT_LOGOUT_TEMPLATE_NAME);
    guiDescriptor.addAdvancedField(logoutTemplateName);

    CheckBoxFieldDescriptor allowPasswordChanges = new CheckBoxFieldDescriptor(FIELD_ALLOW_PASSWORD_CHANGES, DESC_ALLOW_PASSWORD_CHANGES);

    allowPasswordChanges.setDefaultValue(DEFAULT_ALLOW_PASSWORD_CHANGES);
    guiDescriptor.addField(allowPasswordChanges);

    TextFieldDescriptor changePasswordTemplateName = new TextFieldDescriptor(FIELD_CHANGE_PASSWORD_TEMPLATE_NAME, "HTML template (in <pf_home>/server/default/conf/template) to render for a user to change their password.  The default value is html.form.change.password.template.html.");

    changePasswordTemplateName.setDefaultValue(DEFAULT_CHANGE_PASSWORD_TEMPLATE_NAME);
    guiDescriptor.addAdvancedField(changePasswordTemplateName);

    TextFieldDescriptor changePasswordMessageTemplateName = new TextFieldDescriptor(FIELD_CHANGE_PASSWORD_MESSAGE_TEMPLATE_NAME, "HTML template (in <pf_home>/server/default/conf/template) to render when a user is being redirected after successfully changing their password. If left blank, users are redirected without explanation.  The default value is html.form.message.template.html.");


    changePasswordMessageTemplateName.setDefaultValue(DEFAULT_CHANGE_PASSWORD_MESSAGE_TEMPLATE_NAME);
    guiDescriptor.addAdvancedField(changePasswordMessageTemplateName);

    TextFieldDescriptor pwmURL = new TextFieldDescriptor(FIELD_PASSWORD_CHANGE_PWM, "A fully-qualified URL to your password management system where users can change their password. If left blank, password changes are handled by this adapter.");
    pwmURL.setDefaultValue("");
    pwmURL.addValidator(new HttpURLValidator(), true);
    guiDescriptor.addField(pwmURL);

    TextFieldDescriptor pwmMessageTemplateName = new TextFieldDescriptor(FIELD_PASSWORD_CHANGE_PWM_MESSAGE_TEMPLATE_NAME, DESC_PASSWORD_CHANGE_PWM_MESSAGE_TEMPLATE_NAME);


    pwmMessageTemplateName.setDefaultValue(DEFAULT_PASSWORD_CHANGE_PWM_MESSAGE_TEMPLATE_NAME);
    guiDescriptor.addAdvancedField(pwmMessageTemplateName);

    CheckBoxFieldDescriptor enableRememberUsername = new CheckBoxFieldDescriptor(FIELD_ENABLE_REMEMBER_USERNAME, DESC_ENABLE_REMEMBER_USERNAME);

    enableRememberUsername.setDefaultValue(false);
    guiDescriptor.addField(enableRememberUsername);

    CheckBoxFieldDescriptor enablePasswordChangeNotification = new CheckBoxFieldDescriptor(FIELD_ENABLE_CHANGE_PASSWORD_EMAIL_NOTIFICATION, DESC_ENABLE_CHANGE_PASSWORD_EMAIL_NOTIFICATION);

    enablePasswordChangeNotification.setDefaultValue(DEFAULT_ENABLE_CHANGE_PASSWORD_EMAIL_NOTIFICATION);
    enablePasswordChangeNotification.setDefaultValue(DEFAULT_ENABLE_CHANGE_PASSWORD_EMAIL_NOTIFICATION);
    guiDescriptor.addField(enablePasswordChangeNotification);


    CheckBoxFieldDescriptor enableExpiringPasswordWarning = new CheckBoxFieldDescriptor(FIELD_ENABLE_EXPIRING_PASSWORD_WARNING, DESC_ENABLE_EXPIRING_PASSWORD_WARNING);

    enableExpiringPasswordWarning.setDefaultValue(false);
    guiDescriptor.addField(enableExpiringPasswordWarning);


    TextFieldDescriptor changePasswordEmailNotificationTemplateName = new TextFieldDescriptor(FIELD_CHANGE_PASSWORD_EMAIL_NOTIFICATION_TEMPLATE_NAME, DESC_CHANGE_PASSWORD_EMAIL_NOTIFICATION_TEMPLATE_NAME);

    changePasswordEmailNotificationTemplateName.setDefaultValue(DEFAULT_CHANGE_PASSWORD_EMAIL_NOTIFICATION_TEMPLATE_NAME);
    guiDescriptor.addAdvancedField(changePasswordEmailNotificationTemplateName);

    TextFieldDescriptor expiringPasswordWarningTemplateName = new TextFieldDescriptor(FIELD_EXPIRING_PASSWORD_WARNING_TEMPLATE_NAME, DESC_EXPIRING_PASSWORD_WARNING_TEMPLATE_NAME);

    expiringPasswordWarningTemplateName.setDefaultValue(DEFAULT_PASSWORD_EXPIRY_TEMPLATE_NAME);
    guiDescriptor.addAdvancedField(expiringPasswordWarningTemplateName);


    TextFieldDescriptor expiringPasswordWarningThresholdDays = new TextFieldDescriptor(FIELD_EXPIRING_PASSWORD_WARNING_THRESHOLD, DESC_EXPIRING_PASSWORD_WARNING_THRESHOLD);

    expiringPasswordWarningThresholdDays.setDefaultValue(DEFAULT_PASSWORD_EXPIRING_WARNING_THRESHOLD);
    guiDescriptor.addAdvancedField(expiringPasswordWarningThresholdDays);

    TextFieldDescriptor expiringPasswordWarningDelay = new TextFieldDescriptor(FIELD_EXPIRING_PASSWORD_WARNING_DELAY, DESC_EXPIRING_PASSWORD_WARNING_DELAY);

    expiringPasswordWarningDelay.setDefaultValue(DEFAULT_PASSWORD_EXPIRING_WARNING_DELAY);
    guiDescriptor.addAdvancedField(expiringPasswordWarningDelay);

    TextFieldDescriptor loginChallengeTemplateName = new TextFieldDescriptor(FIELD_LOGIN_CHALLENGE_TEMPLATE_NAME, DESC_LOGIN_CHALLENGE_TEMPLATE_NAME);

    loginChallengeTemplateName.setDefaultValue(DEFAULT_LOGIN_CHALLENGE_TEMPLATE_NAME);
    guiDescriptor.addAdvancedField(loginChallengeTemplateName);


    TextFieldDescriptor rememberUsernameLifetime = new TextFieldDescriptor(FIELD_REMEMBER_USERNAME_LIFETIME, DESC_REMEMBER_USERNAME_LIFETIME);

    rememberUsernameLifetime.setDefaultValue(DEFAULT_REMEMBER_USERNAME_LIFETIME);
    guiDescriptor.addAdvancedField(rememberUsernameLifetime);

    CheckBoxFieldDescriptor allowUsernameEdits = new CheckBoxFieldDescriptor(FIELD_ALLOW_USERNAME_EDITS, DESC_ALLOW_USERNAME_EDIT);

    allowUsernameEdits.setDefaultValue(false);
    guiDescriptor.addAdvancedField(allowUsernameEdits);

    CheckBoxFieldDescriptor trackAuthnTime = new CheckBoxFieldDescriptor(FIELD_TRACK_AUTHN_TIME, DESC_TRACK_AUTHN_TIME);
    trackAuthnTime.setDefaultValue(true);
    guiDescriptor.addAdvancedField(trackAuthnTime);

    TextFieldDescriptor pwChangeReauthDelay = new TextFieldDescriptor(FIELD_PASSWORD_CHANGE_REAUTH_DELAY, DESC_PASSWORD_CHANGE_REAUTH_DELAY);

    pwChangeReauthDelay.setDefaultValue(DEFAULT_PASSWORD_CHANGE_REAUTH_DELAY);
    pwChangeReauthDelay.addValidator(new FieldValidator()
    {
      private static final long serialVersionUID = 20121113L;

      private static final int lowerBound = 0;
      private static final int upperBound = 60000;

      public void validate(org.sourceid.saml20.adapter.conf.Field field)
              throws ValidationException
      {
        if ((field.getValue() != null) && (field.getValue().length() != 0))
        {
          IntegerValidator validator = new IntegerValidator(0, 60000);
          validator.validate(field);
        }
      }
    });
    guiDescriptor.addAdvancedField(pwChangeReauthDelay);

    //@TODO

    //List<AbstractSelectionFieldDescriptor.OptionValue> forgotPwdOptions = new ArrayList();
    //forgotPwdOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("Email One-Time Link", "OTL"));
    //forgotPwdOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("Email One-Time Password", "OTP"));
    //forgotPwdOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("PingID", "PingID"));
    //forgotPwdOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("Text Message", "SMS"));
    //forgotPwdOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("None", "NONE"));
    //RadioGroupFieldDescriptor forgotPwdRadioGroup = new RadioGroupFieldDescriptor("Password Reset Type", "Select the method to use for self-service password reset. Depending on the selected method, additional settings are required to complete the configuration.", forgotPwdOptions);

    // forgotPwdRadioGroup.setDefaultValue("NONE");
    //  forgotPwdRadioGroup.setDefaultForLegacyConfig("NONE");
    //guiDescriptor.addField(forgotPwdRadioGroup);*/
    CheckBoxFieldDescriptor emailReset = new CheckBoxFieldDescriptor(FIELD_RESET_TYPE_OTP_NAME, RESET_TYPE_OTP_VALUE);
    emailReset.setDefaultValue(true);
    guiDescriptor.addField(emailReset);

    CheckBoxFieldDescriptor pingIdReset = new CheckBoxFieldDescriptor(RESET_TYPE_PINGID_NAME, RESET_TYPE_PINGID_VALUE);
    pingIdReset.setDefaultValue(true);
    guiDescriptor.addField(pingIdReset);

    CheckBoxFieldDescriptor smsReset = new CheckBoxFieldDescriptor(RESET_TYPE_SMS_NAME, RESET_TYPE_SMS_VALUE);
    smsReset.setDefaultValue(true);
    guiDescriptor.addField(smsReset);


    CheckBoxFieldDescriptor enableUnlock = new CheckBoxFieldDescriptor(FIELD_ACCOUNT_UNLOCK, DESC_ACCOUNT_UNLOCK);
    enableUnlock.setDefaultValue(false);
    guiDescriptor.addField(enableUnlock);

    SelectFieldDescriptor lipSelectFieldDescriptor = new LocalIdentityProfileFieldDescriptor("Local Identity Profile", "Optionally associate this instance with a Local Identity Profile.");


    guiDescriptor.addField(lipSelectFieldDescriptor);



    TextFieldDescriptor forgotPasswordTemplateName = new TextFieldDescriptor(FIELD_RESET_PASSWORD_TEMPLATE_USERNAME_INPUT, DESC_RESET_PASSWORD_TEMPLATE_USERNAME_INPUT);

    forgotPasswordTemplateName.setDefaultValue(DEFAULT_RESET_PASSWORD_TEMPLATE_USERNAME_INPUT);
    guiDescriptor.addAdvancedField(forgotPasswordTemplateName);

    TextFieldDescriptor codeTemplateName = new TextFieldDescriptor(FIELD_RESET_PASSWORD_TEMPLATE_CODE_INPUT, DESC_RESET_PASSWORD_TEMPLATE_CODE_INPUT);

    codeTemplateName.setDefaultValue(DEFAULT_RESET_PASSWORD_TEMPLATE_CODE_INPUT);
    guiDescriptor.addAdvancedField(codeTemplateName);

    TextFieldDescriptor changeTemplateName = new TextFieldDescriptor(FIELD_RESET_PASSWORD_TEMPLATE_CHANGE_INPUT, DESC_RESET_PASSWORD_TEMPLATE_CHANGE_INPUT);

    changeTemplateName.setDefaultValue(DEFAULT_RESET_PASSWORD_TEMPLATE_CHANGE_INPUT);
    guiDescriptor.addAdvancedField(changeTemplateName);

    TextFieldDescriptor errorTemplateName = new TextFieldDescriptor(FIELD_RESET_PASSWORD_TEMPLATE_ERROR_INPUT, DESC_RESET_PASSWORD_TEMPLATE_ERROR_INPUT);

    errorTemplateName.setDefaultValue(DEFAULT_RESET_PASSWORD_TEMPLATE_ERROR_INPUT);
    guiDescriptor.addAdvancedField(errorTemplateName);

    TextFieldDescriptor successTemplateName = new TextFieldDescriptor(FIELD_RESET_PASSWORD_TEMPLATE_SUCCESS_INPUT, DESC_RESET_PASSWORD_TEMPLATE_SUCCESS_INPUT);

    successTemplateName.setDefaultValue(DEFAULT_RESET_PASSWORD_TEMPLATE_SUCCESS_INPUT);
    guiDescriptor.addAdvancedField(successTemplateName);

    TextFieldDescriptor accountUnlockTemplateName = new TextFieldDescriptor(FIELD_ACCOUNT_UNLOCK_TEMPLATE, DESC_ACCOUNT_UNLOCK_TEMPLATE);

    accountUnlockTemplateName.setDefaultValue(DEFAULT_ACCOUNT_UNLOCK_TEMPLATE);
    guiDescriptor.addAdvancedField(accountUnlockTemplateName);



    TextFieldDescriptor numChars = new TextFieldDescriptor(FIELD_CODE_NUMCHARS_INPUT, DESC_CODE_NUMCHARS_INPUT);

    numChars.setDefaultValue(DEFAULT_CODE_NUMCHARS_INPUT);
    numChars.addValidator(new FieldValidator()
    {
      private static final long serialVersionUID = 1L;

      private static final int lowerBound = 5;
      private static final int upperBound = 100;

      public void validate(org.sourceid.saml20.adapter.conf.Field field)
              throws ValidationException
      {
        if ((field.getValue() != null) && (field.getValue().length() != 0))
        {
          IntegerValidator validator = new IntegerValidator(5, 100);
          validator.validate(field);
        }
      }
    });
    guiDescriptor.addAdvancedField(numChars);

    TextFieldDescriptor expiration = new TextFieldDescriptor(FIELD_CODE_EXPIRATION_INPUT, DESC_CODE_EXPIRATION_INPUT);

    expiration.setDefaultValue(DEFAULT_CODE_EXPIRATION_INPUT);
    expiration.addValidator(new FieldValidator()
    {
      private static final long serialVersionUID = 1L;

      private static final int lowerBound = 1;
      private static final int upperBound = 999;

      public void validate(org.sourceid.saml20.adapter.conf.Field field)
              throws ValidationException
      {
        if ((field.getValue() != null) && (field.getValue().length() != 0))
        {
          IntegerValidator validator = new IntegerValidator(1, 999);
          validator.validate(field);
        }
      }
    });
    expiration.setLabel("Password Reset Token Validity Time");
    guiDescriptor.addAdvancedField(expiration);


    UploadFileFieldDescriptor pingidPropertiesField = new UploadFileFieldDescriptor(FIELD_PINGID_PROPERTIES, DESC_PINGID_PROPERTIES, true);
    guiDescriptor.addAdvancedField(pingidPropertiesField);

    guiDescriptor.addValidator(new com.pingidentity.adapters.htmlform.validators.HtmlFormConfigurationValidator());

    CheckBoxFieldDescriptor enableUsernameRecovery = new CheckBoxFieldDescriptor(FIELD_ENABLE_USERNAME_RECOVERY, DESC_ENABLE_USERNAME_RECOVERY);
    enableUsernameRecovery.setDefaultForLegacyConfig(Boolean.FALSE.toString());
    enableUsernameRecovery.setDefaultValue(true);
    guiDescriptor.addField(enableUsernameRecovery);

    CheckBoxFieldDescriptor requireVerifiedEmail = new CheckBoxFieldDescriptor(FIELD_REQUIRE_VERIFIED_EMAIL, DESC_REQUIRE_VERIFIED_EMAIL);
    requireVerifiedEmail.setDefaultValue(false);
    requireVerifiedEmail.setDefaultForLegacyConfig(Boolean.FALSE.toString());
    guiDescriptor.addAdvancedField(requireVerifiedEmail);

    TextFieldDescriptor usernameRecoveryTemplate = new TextFieldDescriptor(FIELD_USERNAME_RECOVERY_TEMPLATE, DESC_USERNAME_RECOVERY_TEMPLATE);
    usernameRecoveryTemplate.setDefaultValue(DEFAULT_USERNAME_RECOVERY_TEMPLATE);
    usernameRecoveryTemplate.setDefaultForLegacyConfig(DEFAULT_USERNAME_RECOVERY_TEMPLATE);
    guiDescriptor.addAdvancedField(usernameRecoveryTemplate);

    TextFieldDescriptor usernameRecoveryInfoTemplate = new TextFieldDescriptor(FIELD_USERNAME_RECOVERY_INFO_TEMPLATE, DESC_USERNAME_RECOVERY_INFO_TEMPLATE);
    usernameRecoveryInfoTemplate.setDefaultValue(DEFAULT_USERNAME_RECOVERY_INFO_TEMPLATE);
    usernameRecoveryInfoTemplate.setDefaultForLegacyConfig(DEFAULT_USERNAME_RECOVERY_INFO_TEMPLATE);
    guiDescriptor.addAdvancedField(usernameRecoveryInfoTemplate);

    TextFieldDescriptor usernameRecoveryEmailTemplate = new TextFieldDescriptor(FIELD_USERNAME_RECOVERY_EMAIL_TEMPLATE, DESC_USERNAME_RECOVERY_EMAIL_TEMPLATE);
    usernameRecoveryEmailTemplate.setDefaultValue(DEFAULT_USERNAME_RECOVERY_EMAIL_TEMPLATE);
    usernameRecoveryEmailTemplate.setDefaultForLegacyConfig(DEFAULT_USERNAME_RECOVERY_EMAIL_TEMPLATE);
    guiDescriptor.addAdvancedField(usernameRecoveryEmailTemplate);

    CheckBoxFieldDescriptor enableCaptchaAuthentication = new CheckBoxFieldDescriptor(FIELD_ENABLE_CAPTCHA_AUTHENTICATION, DESC_ENABLE_CAPTCHA_AUTHENTICATION);
    enableCaptchaAuthentication.setDefaultForLegacyConfig(Boolean.FALSE.toString());
    enableCaptchaAuthentication.setDefaultValue(DEFAULT_ENABLE_CAPTCHA_AUTHENTICATION);
    guiDescriptor.addAdvancedField(enableCaptchaAuthentication);

    CheckBoxFieldDescriptor enableCaptchaPasswordChange = new CheckBoxFieldDescriptor(FIELD_ENABLE_CAPTCHA_PASSWORD_CHANGE, DESC_ENABLE_CAPTCHA_PASSWORD_CHANGE);
    enableCaptchaPasswordChange.setDefaultForLegacyConfig(Boolean.FALSE.toString());
    enableCaptchaPasswordChange.setDefaultValue(DEFAULT_ENABLE_CAPTCHA_PASSWORD_CHANGE);
    guiDescriptor.addAdvancedField(enableCaptchaPasswordChange);

    CheckBoxFieldDescriptor enableCaptchaAccountUnlock = new CheckBoxFieldDescriptor(FIELD_ENABLE_CAPTCHA_PASS_RESET_ACCOUNT_UNLOCK, DESC_ENABLE_CAPTCHA_PASS_RESET_ACCOUNT_UNLOCK);
    enableCaptchaAccountUnlock.setDefaultForLegacyConfig(Boolean.FALSE.toString());
    enableCaptchaAccountUnlock.setDefaultValue(DEFAULT_ENABLE_CAPTCHA_PASS_RESET_ACCOUNT_UNLOCK);
    guiDescriptor.addAdvancedField(enableCaptchaAccountUnlock);

    CheckBoxFieldDescriptor enableCaptchaUsernameRecovery = new CheckBoxFieldDescriptor(FIELD_ENABLE_CAPTCHA_USERNAME_RECOVERY, DESC_ENABLE_CAPTCHA_USERNAME_RECOVERY);
    enableCaptchaUsernameRecovery.setDefaultForLegacyConfig(Boolean.FALSE.toString());
    enableCaptchaUsernameRecovery.setDefaultValue(DEFAULT_ENABLE_CAPTCHA_USERNAME_RECOVERY);
    guiDescriptor.addAdvancedField(enableCaptchaUsernameRecovery);

    LinkDescriptor changePasswordDirectLink = new LinkDescriptor(FIELD_CHANGE_PASSWORD_ENDPOINT, CHANGE_PASSWORD_ENDPOINT);
    guiDescriptor.addSummaryDescriptor(changePasswordDirectLink);

    LinkDescriptor passwordResetDirectLink = new LinkDescriptor(FIELD_PASSWORD_RESET_ENDPOINT, PASSWORD_RESET_ENDPOINT);
    guiDescriptor.addSummaryDescriptor(passwordResetDirectLink);

    guiDescriptor.addPreRenderCallback(new PreRenderCallback()
    {
      public void summaryPageCallback(List<ReadOnlyDescriptor> summaryFields, org.sourceid.saml20.adapter.conf.Configuration configuration)
      {
        for (Iterator<ReadOnlyDescriptor> iterator = summaryFields.iterator(); iterator.hasNext();)
        {

          ReadOnlyDescriptor descriptor = (ReadOnlyDescriptor)iterator.next();

          if ("Change Password Endpoint".equals(descriptor.getName()))
          {
            if (!configuration.getBooleanFieldValue(FIELD_ALLOW_PASSWORD_CHANGES))
            {
              iterator.remove();
            }
            else if ((descriptor instanceof LinkDescriptor))
            {

              String pwdChgMgmtUrl = configuration.getFieldValue(FIELD_PASSWORD_CHANGE_PWM);
              if (org.apache.commons.lang.StringUtils.isNotBlank(pwdChgMgmtUrl))
              {
                ((LinkDescriptor)descriptor).setLink(pwdChgMgmtUrl);
              }
              else
              {
                ((LinkDescriptor)descriptor).setLink(CHANGE_PASSWORD_ENDPOINT);
              }
            }
          }
          else if (("Password Reset Endpoint".equals(descriptor.getName())) && (ForgotPasswordHtmlFormIdpAuthnAdapter.isResetTypeNone(configuration)))
          {
            iterator.remove();
          }

        }
      }
    });
    return guiDescriptor;
  }


  public Set<String> createAttributeContract()
  {
    Set<String> attrNames = new HashSet();
    attrNames.add(ATTR_NAME_USERID);
    attrNames.add(ATTR_NAME_REQUESTEDACTION);
    return attrNames;
  }
  private static class PcvRowValidator implements EnhancedRowValidator, Serializable {
    public void validate(org.sourceid.saml20.adapter.conf.FieldList fieldsInRow) throws ValidationException
    {}

    public void validate(org.sourceid.saml20.adapter.conf.FieldList fieldsInRow, org.sourceid.saml20.adapter.conf.Configuration configuration) throws ValidationException { List<String> adapters = new ArrayList();
      for (Row row : configuration.getTable("Credential Validators").getRows())
      {
        String pcvName = row.getFieldValue("Password Credential Validator Instance");
        if (adapters.contains(pcvName))
        {
          throw new ValidationException("Password Credential Validator '" + pcvName + "' has already been added");
        }

        adapters.add(pcvName);
      }
    }


    private static final long serialVersionUID = 1L;
  }
}
