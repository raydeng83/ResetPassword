package com.pingidentity.adapters.kerberos.idp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Enumeration;
import jcifs.spnego.asn1.ASN1OctetString;
import jcifs.spnego.asn1.ASN1Sequence;
import jcifs.spnego.asn1.ASN1TaggedObject;
import jcifs.spnego.asn1.DERBitString;
import jcifs.spnego.asn1.DERInputStream;
import jcifs.spnego.asn1.DERObjectIdentifier;
import jcifs.spnego.asn1.DERUnknownTag;

public class SpnegoParser
{
  private byte[] mechanismToken;
  private byte[] mechanismListMIC;
  private String[] mechanisms;
  private int contextFlags;
  
  public void parse(byte[] token)
    throws IOException
  {
    ByteArrayInputStream tokenStream = new ByteArrayInputStream(token);
    DERInputStream der = new DERInputStream(tokenStream);
    DERUnknownTag constructed = (DERUnknownTag)der.readObject();
    if (constructed.getTag() != 96)
    {
      throw new IOException("Malformed NegTokenInit.");
    }
    tokenStream = new ByteArrayInputStream(constructed.getData());
    der = new DERInputStream(tokenStream);
    
    DERObjectIdentifier spnego = (DERObjectIdentifier)der.readObject();
    
    ASN1TaggedObject tagged = (ASN1TaggedObject)der.readObject();
    ASN1Sequence sequence = ASN1Sequence.getInstance(tagged, true);
    Enumeration fields = sequence.getObjects();
    while (fields.hasMoreElements()) {
      tagged = (ASN1TaggedObject)fields.nextElement();
      switch (tagged.getTagNo()) {
      case 0: 
        sequence = ASN1Sequence.getInstance(tagged, true);
        String[] mechanisms = new String[sequence.size()];
        for (int i = mechanisms.length - 1; i >= 0; i--)
        {
          DERObjectIdentifier mechanism = (DERObjectIdentifier)sequence.getObjectAt(i);
          mechanisms[i] = mechanism.getId();
        }
        setMechanisms(mechanisms);
        break;
      case 1: 
        DERBitString contextFlags = DERBitString.getInstance(tagged, true);
        
        setContextFlags(contextFlags.getBytes()[0] & 0xFF);
        break;
      
      case 2: 
        ASN1OctetString mechanismToken = ASN1OctetString.getInstance(tagged, true);
        setMechanismToken(mechanismToken.getOctets());
        break;
      
      case 3: 
        ASN1OctetString mechanismListMIC = ASN1OctetString.getInstance(tagged, true);
        setMechanismListMIC(mechanismListMIC.getOctets());
        break;
      default: 
        throw new IOException("Malformed token field.");
      }
    }
  }
  
  public byte[] getMechanismListMIC()
  {
    return this.mechanismListMIC;
  }
  
  public void setMechanismListMIC(byte[] mechanismListMIC) {
    this.mechanismListMIC = mechanismListMIC;
  }
  
  public byte[] getMechanismToken() {
    return this.mechanismToken;
  }
  
  public void setMechanismToken(byte[] mechanismToken) {
    this.mechanismToken = mechanismToken;
  }
  
  public String[] getMechanisms() {
    return this.mechanisms;
  }
  
  public void setMechanisms(String[] mechanisms) {
    this.mechanisms = mechanisms;
  }
  
  public int getContextFlags() {
    return this.contextFlags;
  }
  
  public void setContextFlags(int contextFlags) {
    this.contextFlags = contextFlags;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\kerberos\idp\SpnegoParser.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */