package com.pingidentity.adapters.kerberos.utils;



public abstract class AdapterSessionFactory
{
  public static AdapterSession getAdapterSession()
  {
    AdapterSession adapterSession;
    
    try
    {
      adapterSession = new AdapterSessionStateSupport();
    }
    catch (NoClassDefFoundError e)
    {
      AdapterSession adapterSession;
      
      adapterSession = new AdapterHttpSession();
    }
    
    return adapterSession;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\kerbero\\utils\AdapterSessionFactory.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */