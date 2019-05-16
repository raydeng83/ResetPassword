package com.efx.pingfed.adapters.htmlform.pwdreset.handler;

import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.model.ApiInfo;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.base64url.Base64;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;


public class ApiHelper
{
  private static Log logger = LogFactory.getLog(ApiHelper.class);
  protected PasswordManagementConfiguration configuration;
  
  public ApiHelper(PasswordManagementConfiguration configuration)
  {
    this.configuration = configuration;
  }
  






  public ApiInfo getUserDetails(String pingIdUsername)
  {
    if ((pingIdUsername == null) || (pingIdUsername.isEmpty())) {
      logger.debug("No PingId username found in getuserDetails");
      return null;
    }
    

    JSONObject reqBody = new JSONObject();
    reqBody.put("getSameDeviceUsers", Boolean.valueOf(false));
    reqBody.put("userName", pingIdUsername);
    
    String requestToken = buildRequestToken(reqBody);
    String pingIDGetUserPath = this.configuration.getPingIdAdminUrl() + "/rest/4/getuserdetails/do";
    return callApi(pingIDGetUserPath, requestToken);
  }
  






  private ApiInfo callApi(String pingIdUrl, String requestToken)
  {
    ApiInfo returnInfo = new ApiInfo();
    try
    {
      URL restUrl = new URL(pingIdUrl);
      HttpURLConnection urlConnection = (HttpURLConnection)restUrl.openConnection();
      urlConnection.setRequestMethod("POST");
      urlConnection.addRequestProperty("Content-Type", "application/json");
      urlConnection.addRequestProperty("Accept", "*/*");
      
      urlConnection.setDoOutput(true);
      OutputStreamWriter outputStreamWriter = new OutputStreamWriter(urlConnection.getOutputStream(), "UTF-8");
      outputStreamWriter.write(requestToken);
      outputStreamWriter.flush();
      outputStreamWriter.close();
      

      int responseCode = urlConnection.getResponseCode();
      logger.debug("Ping API call to: " + pingIdUrl + " returned status: " + responseCode);
      
      InputStream is = null;
      if (responseCode >= 400) {
        is = urlConnection.getErrorStream();
      } else {
        is = urlConnection.getInputStream();
      }
      
      String stringJWS = IOUtils.toString(is, urlConnection.getContentEncoding());
      returnInfo.setSuccess(responseCode == 200);
      urlConnection.disconnect();
      
      JSONObject responsePayload = parseResponse(stringJWS);
      returnInfo.setPayload(responsePayload);
      
      if (responsePayload != null) {
        logger.trace("Response from API: " + responsePayload.toJSONString());
        returnInfo.setErrorId(((Long)responsePayload.get("errorId")).longValue());
        returnInfo.setErrorMessage((String)responsePayload.get("errorMsg"));
        returnInfo.setMessageId((String)responsePayload.get("uniqueMsgId"));
        
        if (returnInfo.getErrorId() != 200L) {
          returnInfo.setSuccess(false);
        }
        logger.debug("errorId: " + responsePayload.get("errorId"));
      }
      else {
        logger.error("Could not parse JWS result from call to: " + pingIdUrl);
        returnInfo.setErrorId(500L);
        returnInfo.setErrorMessage("Could not parse JWS");
        returnInfo.setSuccess(false);
      }
    }
    catch (IOException e) {
      logger.error("Error calling: " + pingIdUrl, e);
      returnInfo.setResponseCode(500);
      returnInfo.setSuccess(false);
    }
    
    return returnInfo;
  }
  







  private String buildRequestToken(JSONObject requestBody)
  {
    JSONObject requestHeader = buildRequestHeader();
    
    JSONObject payload = new JSONObject();
    payload.put("reqHeader", requestHeader);
    payload.put("reqBody", requestBody);
    
    JsonWebSignature jws = new JsonWebSignature();
    
    jws.setAlgorithmHeaderValue("HS256");
    jws.setHeader("org_alias", this.configuration.getPingIdOrgAlias());
    jws.setHeader("token", this.configuration.getPingIdToken());
    
    jws.setPayload(payload.toJSONString());
    

    HmacKey key = new HmacKey(Base64.decode(this.configuration.getPingIdBase64Key()));
    jws.setKey(key);
    
    String jwsCompactSerialization = null;
    try {
      jwsCompactSerialization = jws.getCompactSerialization();
    } catch (JoseException e) {
      logger.error("Error compacting JWS", e);
    }
    
    return jwsCompactSerialization;
  }
  




  private JSONObject buildRequestHeader()
  {
    SimpleDateFormat PINGID_DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    JSONObject reqHeader = new JSONObject();
    reqHeader.put("locale", "en");
    reqHeader.put("orgAlias", this.configuration.getPingIdOrgAlias());
    reqHeader.put("secretKey", this.configuration.getPingIdToken());
    reqHeader.put("timestamp", PINGID_DATE_FORMAT.format(new Date()));
    reqHeader.put("version", "4.9");
    
    return reqHeader;
  }
  





  private JSONObject parseResponse(String stringJWS)
  {
    JSONParser parser = new JSONParser();
    JsonWebSignature responseJWS = new JsonWebSignature();
    String payload = stringJWS;
    
    JSONObject responsePayloadJSON = null;
    try
    {
      if (!stringJWS.startsWith("{"))
      {
        responseJWS.setCompactSerialization(stringJWS);
        HmacKey key = new HmacKey(Base64.decode(this.configuration.getPingIdBase64Key()));
        responseJWS.setKey(key);
        payload = responseJWS.getPayload();
      }
      
      responsePayloadJSON = (JSONObject)parser.parse(payload);
      

      if (responsePayloadJSON.containsKey("responseBody")) {
        responsePayloadJSON = (JSONObject)responsePayloadJSON.get("responseBody");
      }
    }
    catch (JoseException|ParseException e) {
      logger.error("Error parsing processing API response", e);
    }
    
    return responsePayloadJSON;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\handler\ApiHelper.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */