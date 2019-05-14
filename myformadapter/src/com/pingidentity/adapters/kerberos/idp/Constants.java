package com.pingidentity.adapters.kerberos.idp;

import org.sourceid.saml20.adapter.gui.validation.impl.HttpURLValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;


















public class Constants
{
  public static final String ADAPTER_NAME = "Kerberos Adapter";
  public static final String ADAPTER_DESCRIPTION = "This adapter uses Kerberos to leverage a AD Domain/Realm login for Web authentication.";
  public static final String ATTR_NAME_USERNAME = "Username";
  public static final String ATTR_NAME_DOMAIN = "Domain/Realm Name";
  public static final String ATTR_NAME_SIDS = "SIDs";
  public static final String FIELD_NAME_AUTHN_CTX = "Authentication Context Value";
  public static final String FIELD_DESC_AUTHN_CTX = "Additional information provided to the SP to assess the level of confidence in the assertion.";
  public static final String FIELD_NAME_REDIRECT_URL = "Error URL Redirect";
  public static final String FIELD_DESC_REDIRECT_URL = "The URL where you want the user redirected when there are errors.";
  public static final RequiredFieldValidator REQUIRED_VALIDATOR = new RequiredFieldValidator();
  public static final HttpURLValidator HTTP_URL_VALIDATOR = new HttpURLValidator();
  public static final String AUTHORIZATION_HEADER = "Authorization";
  public static final String NEGOTIATE_HEADER = "Negotiate";
  public static final String FIELD_NAME_DOMAIN_NAME = "Domain/Realm Name";
  public static final String FIELD_DESC_DOMAIN_NAME = "Select the Domain/Realm Name configured via Active Directory Domains/Kerberos Realms.  To Add/Modify/Remove a Domain/Realm, use the Manage Active Directory Domains/Kerberos Realms button at the bottom of this screen.";
  public static final String FIELD_NAME_ERROR_TEMPLATE_KERB_ONLY = "Error Template";
  public static final String FIELD_DESC_ERROR_TEMPLATE_KERB_ONLY = "Provides a template (<pf_home>/server/default/conf/template/kerberos.error.template.html) to standardize browser behavior when authentication fails.";
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\kerberos\idp\Constants.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */