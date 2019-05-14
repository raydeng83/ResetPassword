package com.pingidentity.provisioner.saas.scim11serviceprovider;

import com.pingidentity.common.util.B64;
import com.pingidentity.pingcommons.util.Closer;
import com.sun.jersey.api.client.ClientHandler;
import com.sun.jersey.api.client.ClientHandlerException;
import com.sun.jersey.api.client.ClientRequest;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.filter.ClientFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import javax.ws.rs.core.MultivaluedMap;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.net.URLCodec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.sourceid.common.Util;







public class OAuth2BearerTokenAuthFilter
  extends ClientFilter
{
  private final Logger logger = LogManager.getLogger(OAuth2BearerTokenAuthFilter.class);
  
  private String tokenEndpoint;
  private String clientId;
  private String clientSecret;
  private String accessToken;
  private String username;
  private String password;
  
  public OAuth2BearerTokenAuthFilter(String tokenEndpoint, String clientId, String clientSecret, String username, String password)
  {
    this.tokenEndpoint = tokenEndpoint;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.username = username;
    this.password = password;
  }
  
  public ClientResponse handle(ClientRequest cr)
    throws ClientHandlerException
  {
    if (this.accessToken == null)
    {
      getAccessToken();
    }
    
    if (!cr.getMetadata().containsKey("Authorization"))
    {
      cr.getMetadata().add("Authorization", "Bearer " + this.accessToken);
    }
    
    return getNext().handle(cr);
  }
  
  public void resetAccessToken()
  {
    this.accessToken = null;
  }
  
  private void getAccessToken()
    throws ClientHandlerException
  {
    HttpURLConnection accessConnection = null;
    InputStream inputStream = null;
    try
    {
      Map<String, String> parms = new HashMap();
      parms.put("grant_type", "password");
      parms.put("username", this.username);
      parms.put("password", this.password);
      
      this.logger.debug("Send request to Token Endpoint = " + this.tokenEndpoint);
      
      accessConnection = (HttpURLConnection)new URL(this.tokenEndpoint).openConnection();
      accessConnection.setRequestMethod("POST");
      accessConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
      String credentials = this.clientId + ":" + this.clientSecret;
      accessConnection.setRequestProperty("Authorization", "Basic " + B64.encode(credentials));
      
      StringBuilder builder = new StringBuilder();
      URLCodec urlCodec = new URLCodec();
      
      try
      {
        for (Map.Entry<String, String> entry : parms.entrySet())
        {
          builder.append((String)entry.getKey()).append("=");
          builder.append(urlCodec.encode((String)entry.getValue())).append("&");
        }
      }
      catch (EncoderException e)
      {
        throw new ClientHandlerException("Problem encoding params.", e);
      }
      
      String postBody = builder.toString();
      byte[] postBodyBytes = Util.utf8bytes(postBody);
      String length = Integer.toString(postBodyBytes.length);
      accessConnection.setRequestProperty("Content-Length", length);
      
      accessConnection.setUseCaches(false);
      accessConnection.setDoInput(true);
      accessConnection.setDoOutput(true);
      try
      {
        OutputStream outputStream = accessConnection.getOutputStream();Throwable localThrowable3 = null;
        try {
          outputStream.write(postBodyBytes);
          outputStream.flush();
        }
        catch (Throwable localThrowable1)
        {
          localThrowable3 = localThrowable1;throw localThrowable1;
        }
        finally
        {
          if (outputStream != null) if (localThrowable3 != null) try { outputStream.close(); } catch (Throwable localThrowable2) { localThrowable3.addSuppressed(localThrowable2); } else outputStream.close();
        }
      } catch (IOException e) {
        throw new ClientHandlerException("Unable to post data to " + this.tokenEndpoint, e);
      }
      
      int responseCode = accessConnection.getResponseCode();
      this.logger.debug("Response Code: " + responseCode);
      
      if (responseCode >= 400)
      {
        inputStream = accessConnection.getErrorStream();
      }
      else
      {
        inputStream = accessConnection.getInputStream();
      }
      

      String encoding = accessConnection.getContentEncoding();
      JSONObject tokenResponse = parseJSONStream(new InputStreamReader(inputStream, encoding != null ? encoding : "UTF-8"));
      this.logger.debug("parsed token endpoint response = " + tokenResponse);
      

      if (responseCode == 200)
      {
        this.accessToken = ((String)tokenResponse.get("access_token"));
        this.logger.debug("accessToken = " + this.accessToken);
      }
      else
      {
        StringBuilder sb = new StringBuilder("Token endpoint returned error: ");
        if (tokenResponse.containsKey("error"))
        {
          sb.append("error=").append(tokenResponse.get("error"));
        }
        
        if (tokenResponse.containsKey("error_description"))
        {
          sb.append(" | error_description=").append(tokenResponse.get("error_description"));
        }
        
        throw new ClientHandlerException("Failed to retreive access token. " + sb.toString());
      }
    }
    catch (Exception e)
    {
      throw new ClientHandlerException("Failed to make access token request", e);
    }
    finally
    {
      Closer.close(inputStream);
      
      if (accessConnection != null)
      {
        accessConnection.disconnect();
      }
    }
  }
  
  private JSONObject parseJSONStream(InputStreamReader streamReader) throws IOException, ParseException
  {
    JSONParser parser = new JSONParser();
    JSONObject tokenResponse = (JSONObject)parser.parse(streamReader);
    return tokenResponse;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\provisioner\saas\scim11serviceprovider\OAuth2BearerTokenAuthFilter.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */