package com.pingidentity.pf.access.token.management.plugins;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.jwk.JsonWebKeySet;
import org.sourceid.common.json.SimpleJsonRespWriter;
import org.sourceid.websso.servlet.adapter.Handler;



public class JwksEndpointHandler
  implements Handler
{
  final String json;
  final String cacheControlValue;
  
  public JwksEndpointHandler(List<JsonWebKey> jwks, int maxAge)
  {
    JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jwks);
    this.json = jsonWebKeySet.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    this.cacheControlValue = ("max-age=" + maxAge);
  }
  
  public void handle(HttpServletRequest req, HttpServletResponse resp)
    throws ServletException, IOException
  {
    SimpleJsonRespWriter sjrw = new SimpleJsonRespWriter();
    sjrw.prepHeaders(resp);
    
    resp.setHeader("Expires", null);
    resp.setHeader("Pragma", null);
    resp.setHeader("Cache-Control", this.cacheControlValue);
    resp.getWriter().print(this.json);
    sjrw.finish(resp);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\access\token\management\plugins\JwksEndpointHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */