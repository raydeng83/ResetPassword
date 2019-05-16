package com.efx.pingfed.adapters.htmlform.pwdreset.handler;

import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.efx.pingfed.adapters.htmlform.pwdreset.handler.ApiHelper;
import com.efx.pingfed.adapters.htmlform.pwdreset.handler.BaseHandler;
import com.pingidentity.adapters.htmlform.pwdreset.model.ApiInfo;
import com.pingidentity.adapters.htmlform.pwdreset.model.PingIDForm;
import com.pingidentity.adapters.htmlform.pwdreset.type.PingIDResult;
import com.pingidentity.sdk.password.ResettablePasswordCredential;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.sourceid.util.log.AttributeMap;
import org.sourceid.websso.bindings.FormPost;
import shaded.pingid.com.pingone.common.mfa.domain.PPMAttribute;
import shaded.pingid.com.pingone.common.mfa.domain.PPMRequest;
import shaded.pingid.com.pingone.common.mfa.domain.PPMResponse;
import shaded.pingid.com.pingone.common.mfa.jwt.JwtHmacUtil;
import shaded.pingid.com.pingone.common.mfa.jwt.JwtResult;
import shaded.pingid.org.jose4j.jwk.OctetSequenceJsonWebKey;
import shaded.pingid.org.jose4j.lang.JoseException;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.*;

public class PingIDHandler
        extends BaseHandler {
    private static Log logger = LogFactory.getLog(PingIDHandler.class);

    private static final int REQUEST_ID_LENGTH = 20;
    private static final char[] REQUEST_ID_ALLOWED_CHARACTERS = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
    private static final String REQUEST_ID_PROVIDER = "SUN";
    private static final String REQUEST_ID_RANDOM_ALG = "SHA1PRNG";
    private ApiHelper apiHelper;

    public PingIDHandler(PasswordManagementConfiguration configuration) {
        super(configuration);
        this.apiHelper = new ApiHelper(configuration);
    }


    public PingIDResult validatePingID(PingIDForm pingIdForm, HttpServletRequest request, HttpServletResponse response) {
        AttributeMap codeAttributes = getStoredCode(request, response);
        if (isExpired(codeAttributes)) {
            logger.debug("Token has expired");
            return PingIDResult.Expired;
        }


        if (pingIdForm.getPpmResponse() == null) {
            logger.error("No ppm response from Authenticator");
            return PingIDResult.AuthFailed;
        }

        PPMResponse ppmResponse;

        try {
            ppmResponse = getPPMResponse(pingIdForm.getPpmResponse());
        } catch (JoseException e) {
            logger.error("Error reading ppm response from Authenticator", e);
            return PingIDResult.AuthFailed;
        }
        if (!"success".equalsIgnoreCase(ppmResponse.getStatus().trim())) {
            logger.debug("Authenticator status failed (error code: " + ppmResponse.getErrorCode() + ", message: " + ppmResponse
                    .getMessage() + ")");

            if ("20516".equals(ppmResponse.getErrorCode().trim())) {
                return PingIDResult.Canceled;
            }
            return PingIDResult.AuthFailed;
        }


        String savedNonce = (String) this.sessionUtil.get("prPPMRequestId", request, response);
        if ((savedNonce == null) || (!savedNonce.equals(ppmResponse.getNonce()))) {
            logger.error("Authenticator response id does not match request id");
            return PingIDResult.AuthFailed;
        }


        logger.debug("PingID Code Successfully Validated");
        return PingIDResult.Success;
    }


    public String getPingUserId(String username, String pcvId) {
        String pingIdUsername = null;
        AttributeMap userAttrs = getAttributes(username, pcvId);
        if (userAttrs != null) {
            ResettablePasswordCredential pcv = getPcv(pcvId);
            pingIdUsername = userAttrs.getSingleValue(pcv.getPingIdUsernameAttribute());
        }
        logger.debug("PingID username (for user: " + username + ") is: " + pingIdUsername);
        return pingIdUsername;
    }


    public boolean isActiveForAuthentication(String pingIdUsername) {
        String status = "";
        ApiInfo apiInfo = this.apiHelper.getUserDetails(pingIdUsername);

        if ((apiInfo.isSuccess()) && (apiInfo.getPayload() != null)) {
            JSONObject userDetails = (JSONObject) apiInfo.getPayload().get("userDetails");

            if (userDetails != null) {
                status = (String) userDetails.get("status");
            }
        }

        boolean active = "ACTIVE".equalsIgnoreCase(status);
        if (!active) {
            logger.debug("Status for PingId user " + pingIdUsername + ": " + status);
        }
        return active;
    }


    public void sendAuthRequest(String pingIdUsername, String returnUrl, HttpServletRequest request, HttpServletResponse response)
            throws JoseException, IOException, Exception {
        if ((pingIdUsername == null) || (pingIdUsername.length() == 0)) {
            throw new Exception("No PingID username provided");
        }

        PPMRequest ppmRequest = generatePPMRequest(pingIdUsername, returnUrl);

        this.sessionUtil.add("prPPMRequestId", ppmRequest.getNonce(), request, response);

        ArrayList<PPMAttribute> additionalAttributes = new ArrayList();
        additionalAttributes.add(new PPMAttribute("isUserAuthenticated", Boolean.toString(true)));

        additionalAttributes.add(new PPMAttribute("saasid", "com.pingidentity.pf.passwordreset"));
        ppmRequest.setAttributes(additionalAttributes);

        String jwtToken = createToken(ppmRequest.toJson());

        Map<String, Object> postParams = new HashMap();
        postParams.put("idp_account_id", this.configuration.getPingIdOrgAlias());
        postParams.put("ppm_request", jwtToken);

        String pingIDAuthenticatorPath = this.configuration.getPingIdAuthenticatorUrl() + "/auth";


        FormPost.post(pingIDAuthenticatorPath, postParams, response);
    }


    private String createToken(String payload)
            throws JoseException, shaded.pingid.org.jose4j.lang.JoseException {
        OctetSequenceJsonWebKey hmacKey = JwtHmacUtil.pingidKeyToWebKey(this.configuration.getPingIdBase64Key());
        String jwt = JwtHmacUtil.sign(payload, hmacKey);
        return jwt;
    }


    private PPMRequest generatePPMRequest(String username, String returnUrl) {
        String requestId = generateRequestId();

        Date date = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(12, this.configuration.getExpirationMinutes());

        PPMRequest ppmRequest = new PPMRequest();
        ppmRequest.setIdpAccountId(this.configuration.getPingIdOrgAlias());
        ppmRequest.setReturnUrl(returnUrl);
        ppmRequest.setSub(username);
        ppmRequest.setJti("");
        ppmRequest.setNonce(requestId);
        ppmRequest.setIss("");
        ppmRequest.setAud("pingidauthenticator");
        ppmRequest.setIat(date.getTime());
        ppmRequest.setExp(cal.getTime().getTime());
        return ppmRequest;
    }


    private PPMResponse getPPMResponse(String payload)
            throws JoseException {
        OctetSequenceJsonWebKey hmacKey = JwtHmacUtil.pingidKeyToWebKey(this.configuration.getPingIdBase64Key());
        JwtResult jwt = JwtHmacUtil.verifySignature(payload, hmacKey);
        PPMResponse ppmResponse = PPMResponse.fromJson(jwt.getPayload());
        return ppmResponse;
    }


    private String generateRequestId() {
        Random random = null;
        try {
            random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            random = new SecureRandom();
        }
        char[] chars = new char[20];
        for (int i = 0; i < 20; i++) {
            int rnd = random.nextInt(REQUEST_ID_ALLOWED_CHARACTERS.length);
            chars[i] = REQUEST_ID_ALLOWED_CHARACTERS[rnd];
        }
        return new String(chars);
    }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\handler\PingIDHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */