package com.pingidentity.pf.access.token.management.plugins;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.xml.security.utils.Base64;
import org.sourceid.websso.servlet.adapter.Handler;




public class X509CertificateEndpointHandler
  implements Handler
{
  private final String message;
  private final Map<String, X509Certificate> certMap;
  static final String PARAMETER_NAME = "v";
  
  public X509CertificateEndpointHandler(String description, Map<String, X509Certificate> certMap)
  {
    this.message = ("Please indicate the " + description + " via the " + "v" + " parameter.");
    this.certMap = certMap;
  }
  
  public void handle(HttpServletRequest req, HttpServletResponse resp)
    throws IOException
  {
    String id = req.getParameter("v");
    
    if (id == null)
    {
      resp.sendError(400, this.message);
    }
    else
    {
      X509Certificate x509Certificate = (X509Certificate)this.certMap.get(id);
      
      if (x509Certificate == null)
      {
        resp.sendError(400, "Unknown Certificate. " + this.message);
      }
      else
      {
        resp.setContentType("text/plain");
        try {
          PrintWriter out = resp.getWriter();Throwable localThrowable3 = null;
          try {
            byte[] derCert = x509Certificate.getEncoded();
            String pemCert = Base64.encode(derCert);
            out.println("-----BEGIN CERTIFICATE-----");
            out.println(pemCert);
            out.println("-----END CERTIFICATE-----");
            out.flush();
          }
          catch (Throwable localThrowable1)
          {
            localThrowable3 = localThrowable1;throw localThrowable1;


          }
          finally
          {


            if (out != null) if (localThrowable3 != null) try { out.close(); } catch (Throwable localThrowable2) { localThrowable3.addSuppressed(localThrowable2); } else out.close();
          }
        } catch (CertificateEncodingException e) {
          throw new IOException("Certificate encoding problem.", e);
        }
      }
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\access\token\management\plugins\X509CertificateEndpointHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */