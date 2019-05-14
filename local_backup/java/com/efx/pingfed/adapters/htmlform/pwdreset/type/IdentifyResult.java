package com.efx.pingfed.adapters.htmlform.pwdreset.type;

public enum IdentifyResult
{
  NoUsername,  UserNotFound,  Error,  CodeSent,  LinkSent,  SmsSent,  SmsNotSent,  NoEmailAddress,  NoMobilePhone,  PingID,  RecoverUsername,  EmailUnverifiedLinkNotSent,  EmailUnverifiedCodeNotSent,  Cancel, UserFound;
  
  private IdentifyResult() {}
}

