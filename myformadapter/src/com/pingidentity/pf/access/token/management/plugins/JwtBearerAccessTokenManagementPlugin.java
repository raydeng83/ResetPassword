package com.pingidentity.pf.access.token.management.plugins;

import com.pingidentity.crypto.SignatureAlgorithm;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import com.pingidentity.sdk.accessgrant.AccessGrant;
import com.pingidentity.sdk.accessgrant.AccessGrantManager;
import com.pingidentity.sdk.oauth20.AccessToken;
import com.pingidentity.sdk.oauth20.IssuedAccessToken;
import com.pingidentity.sdk.oauth20.Scope;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import javax.security.auth.x500.X500PrivateCredential;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.mutable.MutableBoolean;
import org.apache.commons.logging.Log;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithm;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey.Factory;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwx.Headers;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.keys.X509Util;
import org.jose4j.lang.JoseException;
import org.sourceid.common.ExceptionUtil;
import org.sourceid.common.IDGenerator;
import org.sourceid.common.ValidationUtil;
import org.sourceid.common.json.SimpleJsonRespWriter;
import org.sourceid.saml20.adapter.attribute.AttrValueSupport;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.gui.AbstractSelectionFieldDescriptor.OptionValue;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.SelectFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TableDescriptor;
import org.sourceid.saml20.adapter.gui.TextAreaFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.HttpsURLValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.IntegerValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.saml20.domain.BearerAccessTokenMgmtPluginInstance;
import org.sourceid.saml20.domain.mgmt.BearerAccessTokenMgmtPluginManager;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.util.log.AttributeMap;
import org.sourceid.websso.servlet.adapter.HandlerRegistry;

public class JwtBearerAccessTokenManagementPlugin implements com.pingidentity.sdk.oauth20.BearerAccessTokenManagementPlugin
{
  public static final String X509_PATH_BY_KID = "/oauth/x509/kid";
  public static final String X509_PATH_BY_X5T = "/oauth/x509/x5t";
  public static final String B64U_ENCODING = "b64u";
  public static final String HEX_ENCODING = "";
  private static Log log = org.apache.commons.logging.LogFactory.getLog(JwtBearerAccessTokenManagementPlugin.class);
  
  private PluginDescriptor pluginDescriptor;
  
  static final String JWS_ALGO = "JWS Algorithm";
  
  static final String TOKEN_LIFETIME = "Token Lifetime";
  
  static final String ACTIVE_SIGNING_CERT = "Active Signing Certificate Key ID";
  
  static final String CLIENT_ID_CLAIM_NAME = "Client ID Claim Name";
  
  static final String SCOPE_CLAIM_NAME = "Scope Claim Name";
  
  static final String ACCESS_GRANT_GUID_CLAIM_NAME = "Access Grant GUID Claim Name";
  
  static final String SPACE_DELIMIT_SCOPE_VALUES = "Space Delimit Scope Values";
  static final String JWT_ID_CLAIM_LENGTH = "JWT ID Claim Length";
  static final String AUDIENCE_CLAIM_VALUE = "Audience Claim Value";
  static final String ISSUER_CLAIM_VALUE = "Issuer Claim Value";
  static final String INCLUDE_KEY_ID_HEADER_PARAMETER = "Include Key ID Header Parameter";
  static final String INCLUDE_X509_THUMB_HEADER_PARAMETER = "Include X.509 Thumbprint Header Parameter";
  static final String SYMMETRIC_KEYS = "Symmetric Keys";
  static final String ACTIVE_SYMMETRIC_KEY = "Active Symmetric Key ID";
  static final String KEY_ID = "Key ID";
  static final String KEY = "Key";
  static final String ENCODING = "Encoding";
  static final String PUBLISH_KEYID_X509_URL = "Publish Key ID X.509 URL";
  static final String PUBLISH_THUMBPRINT_X509_URL = "Publish Thumbprint X.509 URL";
  static final String JWKS_PATH = "JWKS Endpoint Path";
  static final String JWKS_PATH_CACHE_AGE = "JWKS Endpoint Cache Duration";
  static final String CERTIFICATES = "Certificates";
  static final String CERTIFICATE = "Certificate";
  static final String JWE_ALGO = "JWE Algorithm";
  static final String JWE_CONTENT_ENCRYPTION_ALGO = "JWE Content Encryption Algorithm";
  static final String ACTIVE_SYMMETRIC_ENCRYPTION_KEY = "Active Symmetric Encryption Key ID";
  static final String ASYMMETRIC_ENCRYPTION_KEY = "Asymmetric Encryption Key";
  static final String ASYMMETRIC_ENCRYPTION_JWKS_URL = "Asymmetric Encryption JWKS URL";
  static final String DEFAULT_CACHE_DURATION = "Default JWKS URL Cache Duration";
  static final String INCLUDE_JWE_KEY_ID_HEADER_PARAMETER = "Include JWE Key ID Header Parameter";
  static final String INCLUDE_JWE_X509_THUMB_HEADER_PARAMETER = "Include JWE X.509 Thumbprint Header Parameter";
  private static final RequiredFieldValidator REQUIRED_FIELD = new RequiredFieldValidator();
  
  private String jwsAlgo;
  private int tokenLife;
  private Map<String, X500PrivateCredential> signingKeys;
  private final Map<String, X509Certificate> kidToCertMap = new HashMap();
  private final Map<String, X509Certificate> thumbToCertMap = new HashMap();
  
  private String activeCertKeyId;
  
  private String x5t;
  
  private Map<String, Key> symmetricKeys;
  
  private String activeMacKeyId;
  
  private String jweAlgo;
  
  private String jweEncAlgo;
  
  private String activeSymmetricEncryptionKeyId;
  private PublicJsonWebKey asymmetricEncryptionJwk;
  private RemoteJwksSupport remoteJwksSupport;
  private boolean includeJweKid;
  private boolean includeJweX5t;
  private boolean includeJwsKid;
  private String scopeClaimName;
  private String clientIdClaimName;
  private String accessGrantGuidClaimName;
  private boolean spaceDelimitScope;
  private int jwtIdClaimLength;
  private String issuerValue;
  private String audienceValue;
  private final CertificateSupport certSupport = new CertificateSupport();
  private final AccessGrantManager accessGrantManager;
  private final BearerAccessTokenMgmtPluginManager tokenPluginManager;
  
  public JwtBearerAccessTokenManagementPlugin()
  {
    this.tokenPluginManager = MgmtFactory.getBearerAccessTokenMgmtPluginMgr();
    this.certSupport.init();
    initDescriptors();
    this.accessGrantManager = MgmtFactory.getAccessGrantManager();
  }
  
  public JwtBearerAccessTokenManagementPlugin(Collection<X500PrivateCredential> x500s, AccessGrantManager agm, BearerAccessTokenMgmtPluginManager tokenPluginManager)
  {
    this.tokenPluginManager = tokenPluginManager;
    this.certSupport.init(x500s);
    initDescriptors();
    this.accessGrantManager = agm;
  }
  
  private void initDescriptors()
  {
    GuiConfigDescriptor gui = new HackGuiConfigDescriptor(null);
    gui.setDescription("A JSON Web Token (JWT) Bearer Access Token Management Plug-in that enables PingFederate to issue (and optionally validate) cryptographically secure self-contained OAuth access tokens.");
    

    String kidDesc = "An identifier for the given key";
    TextFieldDescriptor keyIdField = new TextFieldDescriptor("Key ID", kidDesc);
    keyIdField.setSize(3);
    keyIdField.addValidator(REQUIRED_FIELD);
    String symmKeysDesc = "A group of keys for use with symmetric encryption and MAC algorithms.";
    TableDescriptor symmetricKeyTable = new TableDescriptor("Symmetric Keys", symmKeysDesc);
    symmetricKeyTable.addRowField(keyIdField);
    TextFieldDescriptor keyField = new TextFieldDescriptor("Key", "Encoded symmetric key", true);
    keyField.setSize(150);
    keyField.addValidator(REQUIRED_FIELD);
    symmetricKeyTable.addRowField(keyField);
    ArrayList<AbstractSelectionFieldDescriptor.OptionValue> encodingOptions = new ArrayList();
    encodingOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("Hex", ""));
    encodingOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("Base64[url]", "b64u"));
    SelectFieldDescriptor keyEncoding = new SelectFieldDescriptor("Encoding", "How the binary key is encoded as a string", encodingOptions);
    symmetricKeyTable.addRowField(keyEncoding);
    symmetricKeyTable.addValidator(new SymmetricKeySupport());
    gui.addTable(symmetricKeyTable);
    
    String certsDesc = "A group of certificates and their corresponding public/private key pairs for use with signatures";
    TableDescriptor certsTable = new TableDescriptor("Certificates", certsDesc);
    certsTable.addRowField(keyIdField);
    String certDesc = "Requires an EC key or RSA key length of at least 2048 bits";
    SelectFieldDescriptor dsigKeypairField = this.certSupport.getCertsDesc("Certificate", certDesc);
    dsigKeypairField.addValidator(REQUIRED_FIELD);
    
    certsTable.addRowField(dsigKeypairField);
    gui.addTable(certsTable);
    
    TextFieldDescriptor tokenLifeDesc = new TextFieldDescriptor("Token Lifetime", "Defines how long, in minutes, an access token is valid.");
    
    tokenLifeDesc.setSize(8);
    tokenLifeDesc.setDefaultValue("120");
    tokenLifeDesc.addValidator(REQUIRED_FIELD);
    tokenLifeDesc.addValidator(new IntegerValidator(1, 35791394), true);
    gui.addField(tokenLifeDesc);
    
    List<AbstractSelectionFieldDescriptor.OptionValue> options = new ArrayList();
    options.add(SelectFieldDescriptor.SELECT_ONE);
    options.add(new AbstractSelectionFieldDescriptor.OptionValue("ECDSA using P-256 and SHA-256", "ES256"));
    options.add(new AbstractSelectionFieldDescriptor.OptionValue("ECDSA using P-384 and SHA-384", "ES384"));
    options.add(new AbstractSelectionFieldDescriptor.OptionValue("ECDSA using P-521 and SHA-512", "ES512"));
    options.add(new AbstractSelectionFieldDescriptor.OptionValue("HMAC using SHA-256", "HS256"));
    options.add(new AbstractSelectionFieldDescriptor.OptionValue("HMAC using SHA-384", "HS384"));
    options.add(new AbstractSelectionFieldDescriptor.OptionValue("HMAC using SHA-512", "HS512"));
    options.add(new AbstractSelectionFieldDescriptor.OptionValue("RSA using SHA-256", "RS256"));
    options.add(new AbstractSelectionFieldDescriptor.OptionValue("RSA using SHA-384", "RS384"));
    options.add(new AbstractSelectionFieldDescriptor.OptionValue("RSA using SHA-512", "RS512"));
    
    if (SignatureAlgorithm.isRSAPSSAvailable())
    {
      options.add(new AbstractSelectionFieldDescriptor.OptionValue("RSASSA-PSS using SHA-256", "PS256"));
      options.add(new AbstractSelectionFieldDescriptor.OptionValue("RSASSA-PSS using SHA-384", "PS384"));
      options.add(new AbstractSelectionFieldDescriptor.OptionValue("RSASSA-PSS using SHA-512", "PS512"));
    }
    
    String desc = "The HMAC or signing algorithm used to protect the integrity of the token. For HMAC, the active symmetric key must be selected below. For RSA or EC, the active signing certificate must be selected. Integrity protection can also be achieved using symmetric encryption, in which case this field can be left unselected.";
    

    SelectFieldDescriptor algo = new SelectFieldDescriptor("JWS Algorithm", desc, options);
    gui.addField(algo);
    
    String activeHmacKeyDesc = "The Key ID of the key to use when producing JWTs using an HMAC-based algorithm.";
    SelectFieldDescriptor activeSymmetricKey = new SelectFieldDescriptor("Active Symmetric Key ID", activeHmacKeyDesc, new String[0]);
    
    gui.addField(activeSymmetricKey);
    
    String doKidDesc = "Indicates whether the Key ID (kid) header parameter will be included in the signature header of the token, which can help identify the appropriate key during verification.";
    
    CheckBoxFieldDescriptor kid = new CheckBoxFieldDescriptor("Include Key ID Header Parameter", doKidDesc);
    kid.setDefaultValue(true);
    gui.addAdvancedField(kid);
    
    String activeCertDesc = "The Key ID of the key pair and certificate to use when producing JWTs using an RSA-based or EC-based algorithm.";
    SelectFieldDescriptor activeCert = new SelectFieldDescriptor("Active Signing Certificate Key ID", activeCertDesc, new String[0]);
    
    gui.addField(activeCert);
    
    String x5tDesc = "Indicates whether the X.509 Certificate Thumbprint (x5t) header parameter will be included in the signature header of the token token, which can help identify the appropriate public key during verification of asymmetrically signed tokens.";
    
    gui.addAdvancedField(new CheckBoxFieldDescriptor("Include X.509 Thumbprint Header Parameter", x5tDesc));
    
    List<AbstractSelectionFieldDescriptor.OptionValue> jweAlgOptions = new ArrayList();
    jweAlgOptions.add(SelectFieldDescriptor.SELECT_ONE);
    jweAlgOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("Direct Encryption with symmetric key", "dir"));
    jweAlgOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("AES-128 Key Wrap", "A128KW"));
    jweAlgOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("AES-192 Key Wrap", "A192KW"));
    jweAlgOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("AES-256 Key Wrap", "A256KW"));
    jweAlgOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("AES-GCM-128 key encryption", "A128GCMKW"));
    jweAlgOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("AES-GCM-192 key encryption", "A192GCMKW"));
    jweAlgOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("AES-GCM-256 key encryption", "A256GCMKW"));
    jweAlgOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("ECDH-ES", "ECDH-ES"));
    jweAlgOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("ECDH-ES with AES-128 Key Wrap", "ECDH-ES+A128KW"));
    jweAlgOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("ECDH-ES with AES-192 Key Wrap", "ECDH-ES+A192KW"));
    jweAlgOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("ECDH-ES with AES-256 Key Wrap", "ECDH-ES+A256KW"));
    jweAlgOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("RSAES OAEP", "RSA-OAEP"));
    
    String jweAlgDesc = "The algorithm used to encrypt or otherwise determine the value of the content encryption key.";
    SelectFieldDescriptor jweAlgo = new SelectFieldDescriptor("JWE Algorithm", jweAlgDesc, jweAlgOptions);
    gui.addField(jweAlgo);
    
    List<AbstractSelectionFieldDescriptor.OptionValue> jweEncOptions = new ArrayList();
    jweEncOptions.add(SelectFieldDescriptor.SELECT_ONE);
    jweEncOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("Composite AES-CBC-128 HMAC-SHA-256", "A128CBC-HS256"));
    jweEncOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("Composite AES-CBC-192 HMAC-SHA-384", "A192CBC-HS384"));
    jweEncOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("Composite AES-CBC-256 HMAC-SHA-512", "A256CBC-HS512"));
    jweEncOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("AES-GCM-128", "A128GCM"));
    jweEncOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("AES-GCM-192", "A192GCM"));
    jweEncOptions.add(new AbstractSelectionFieldDescriptor.OptionValue("AES-GCM-256", "A256GCM"));
    
    String jweEncDesc = "The content encryption algorithm used to perform authenticated encryption on the plaintext payload of the token.";
    SelectFieldDescriptor jweEncAlgo = new SelectFieldDescriptor("JWE Content Encryption Algorithm", jweEncDesc, jweEncOptions);
    gui.addField(jweEncAlgo);
    
    String activeSymmEncKeyDesc = "The Key ID of the key to use when using a symmetric encryption algorithm.";
    SelectFieldDescriptor activeSymmetricEncKey = new SelectFieldDescriptor("Active Symmetric Encryption Key ID", activeSymmEncKeyDesc, new String[0]);
    gui.addField(activeSymmetricEncKey);
    
    String asymmetricEncKeyDesc = "An asymmetric encryption public key, which can be in either JWK format or a certificate.";
    TextAreaFieldDescriptor asymmetricEncKey = new TextAreaFieldDescriptor("Asymmetric Encryption Key", asymmetricEncKeyDesc, 4, 18);
    asymmetricEncKey.addValidator(new PublicJwkSupport(), true);
    gui.addField(asymmetricEncKey);
    
    String jwksUrlDesc = "The HTTPS URL of a JSON Web Key Set endpoint that has public key(s) for encryption.";
    TextFieldDescriptor jwks = new TextFieldDescriptor("Asymmetric Encryption JWKS URL", jwksUrlDesc);
    jwks.addValidator(new HttpsURLValidator(), true);
    gui.addField(jwks);
    
    String defaultCacheDesc = "The default time in minutes to cache the content of the Asymmetric Encryption JWKS URL, which will be used when no cache directives are included or they indicate that the content has already expired.";
    

    TextFieldDescriptor defaultJwksCache = new TextFieldDescriptor("Default JWKS URL Cache Duration", "The default time in minutes to cache the content of the Asymmetric Encryption JWKS URL, which will be used when no cache directives are included or they indicate that the content has already expired.");
    defaultJwksCache.setDefaultValue("720");
    defaultJwksCache.setDefaultForLegacyConfig("720");
    defaultJwksCache.addValidator(new IntegerValidator(0, 86400), true);
    gui.addAdvancedField(defaultJwksCache);
    
    String doJweKidDesc = "Indicates whether the Key ID (kid) header parameter will be included in the encryption header of the token, which can help identify the appropriate key during decryption.";
    
    CheckBoxFieldDescriptor jweKid = new CheckBoxFieldDescriptor("Include JWE Key ID Header Parameter", doJweKidDesc);
    jweKid.setDefaultValue(true);
    jweKid.setDefaultForLegacyConfig(Boolean.toString(true));
    gui.addAdvancedField(jweKid);
    
    String doJweX5cDesc = "Indicates whether the X.509 Certificate Thumbprint (x5t) header parameter will be included in the encryption header of the token, which can help identify the appropriate key during decryption.";
    
    CheckBoxFieldDescriptor jweX5c = new CheckBoxFieldDescriptor("Include JWE X.509 Thumbprint Header Parameter", doJweX5cDesc);
    gui.addAdvancedField(jweX5c);
    
    int nameSize = 20;
    String cidClaimDesc = "The name of the JWT claim used to represent the OAuth Client ID (omitted, if blank).";
    TextFieldDescriptor claimName = new TextFieldDescriptor("Client ID Claim Name", cidClaimDesc);
    claimName.addValidator(new ReservedClaimNamesValidator());
    claimName.setDefaultValue("client_id");
    claimName.setSize(nameSize);
    gui.addAdvancedField(claimName);
    String scopeClaimDesc = "The name of the JWT claim used to represent the scope of the grant (omitted, if blank).";
    claimName = new TextFieldDescriptor("Scope Claim Name", scopeClaimDesc);
    claimName.addValidator(new ReservedClaimNamesValidator());
    claimName.setDefaultValue("scope");
    claimName.setSize(nameSize);
    gui.addAdvancedField(claimName);
    String spaceScopeDesc = "Select checkbox to indicate that multiple scope strings will be delimited by spaces rather than represented as a JSON array.";
    gui.addAdvancedField(new CheckBoxFieldDescriptor("Space Delimit Scope Values", spaceScopeDesc));
    String issDesc = "Indicates the value of the Issuer (iss) claim in the JWT (omitted, if blank).";
    TextFieldDescriptor issuerVal = new TextFieldDescriptor("Issuer Claim Value", issDesc);
    int valueSize = 45;
    issuerVal.setSize(valueSize);
    gui.addAdvancedField(issuerVal);
    String audDesc = "Indicates the value of the Audience (aud) claim in the JWT (omitted, if blank).";
    TextFieldDescriptor audVal = new TextFieldDescriptor("Audience Claim Value", audDesc);
    audVal.setSize(valueSize);
    gui.addAdvancedField(audVal);
    
    String jtiDesc = "Indicates the number of characters of the JWT ID (jti) claim in the JWT (omitted, if zero).";
    TextFieldDescriptor jwtId = new TextFieldDescriptor("JWT ID Claim Length", jtiDesc);
    jwtId.setDefaultValue("0");
    jwtId.setSize(4);
    jwtId.addValidator(REQUIRED_FIELD);
    jwtId.addValidator(new IntegerValidator(0, 500), true);
    gui.addAdvancedField(jwtId);
    
    String guidDesc = "The name of the JWT claim used to carry the persistent access grant GUID (omitted, if blank). If the claim is present during validation, the grant database is consulted to ensure the grant is still good.";
    
    TextFieldDescriptor guidClaimName = new TextFieldDescriptor("Access Grant GUID Claim Name", guidDesc);
    guidClaimName.addValidator(new ReservedClaimNamesValidator());
    guidClaimName.setSize(nameSize);
    gui.addAdvancedField(guidClaimName);
    
    String jwksEndpointDesc = "Path on the PingFederate server to publish a JSON Web Key Set with the keys/certificates that can be used for signature verification. Must include the initial slash (example: /oauth/jwks). The resulting URL will be https://<pf_host>:<port>/ext/<JWKS Endpoint Path>). If specified, the path must be unique across all plugin instances, including child instances.";
    


    TextFieldDescriptor jwksEndpoint = new TextFieldDescriptor("JWKS Endpoint Path", "Path on the PingFederate server to publish a JSON Web Key Set with the keys/certificates that can be used for signature verification. Must include the initial slash (example: /oauth/jwks). The resulting URL will be https://<pf_host>:<port>/ext/<JWKS Endpoint Path>). If specified, the path must be unique across all plugin instances, including child instances.");
    jwksEndpoint.addValidator(new com.pingidentity.adapters.htmlform.validators.SubPathValidator(), true);
    gui.addAdvancedField(jwksEndpoint);
    
    String jwksCacheDesc = "How long, in minutes, to tell clients that they can cache the content from the JWKS Endpoint Path.";
    TextFieldDescriptor jwksCache = new TextFieldDescriptor("JWKS Endpoint Cache Duration", "How long, in minutes, to tell clients that they can cache the content from the JWKS Endpoint Path.");
    jwksCache.setDefaultValue("720");
    jwksCache.setDefaultForLegacyConfig("720");
    jwksCache.addValidator(new IntegerValidator(0, 525600), true);
    gui.addAdvancedField(jwksCache);
    
    String kidEndptDesc = "Indicates whether the certificates will be made accessible by Key ID at https://<pf_host>:<port>/ext/oauth/x509/kid?v=<id>";
    
    gui.addAdvancedField(new CheckBoxFieldDescriptor("Publish Key ID X.509 URL", kidEndptDesc));
    String x5tEndptDesc = "Indicates whether the certificates will be made accessible by certificate thumbprint at https://<pf_host>:<port>/ext/oauth/x509/x5t?v=<base64url encoded SHA-1 thumbprint>";
    
    gui.addAdvancedField(new CheckBoxFieldDescriptor("Publish Thumbprint X.509 URL", x5tEndptDesc));
    
    gui.addPreRenderCallback(new KeySelectPreRenderCallback("Certificates", activeCert));
    gui.addPreRenderCallback(new KeySelectPreRenderCallback("Symmetric Keys", activeSymmetricKey));
    gui.addPreRenderCallback(new KeySelectPreRenderCallback("Symmetric Keys", activeSymmetricEncKey));
    

    gui.addValidator(new ConfigValidator(this.certSupport));
    
    this.pluginDescriptor = new PluginDescriptor("JSON Web Tokens", this, gui, getVersion());
  }
  


  public IssuedAccessToken issueAccessToken(Map<String, AttributeValue> attributes, Scope scope, String clientId, String accessGrantGuid)
  {
    Map<String, Object> payloadMap = new LinkedHashMap();
    
    scope = scope == null ? new Scope(new String[0]) : scope;
    addIfNameNotBlankAndValueNotNull(payloadMap, this.scopeClaimName, this.spaceDelimitScope ? scope.getScopeStr() : new ArrayList(scope
      .getScopeSet()));
    
    addIfNameNotBlankAndValueNotNull(payloadMap, this.clientIdClaimName, clientId);
    
    addIfNameNotBlankAndValueNotNull(payloadMap, this.accessGrantGuidClaimName, accessGrantGuid);
    
    addIfValueNotBlank(payloadMap, "iss", this.issuerValue);
    addIfValueNotBlank(payloadMap, "aud", this.audienceValue);
    
    if (this.jwtIdClaimLength > 0)
    {
      addToPayload(payloadMap, "jti", IDGenerator.rndAlphaNumeric(this.jwtIdClaimLength));
    }
    
    SimpleJsonRespWriter.prepareAttributeMap(new AttributeMap(attributes), payloadMap);
    
    NumericDate expiresAt = getExpiresAt(attributes);
    addToPayload(payloadMap, "exp", Long.valueOf(expiresAt.getValue()));
    
    String payload = JsonUtil.toJson(payloadMap);
    String token = null;
    
    boolean doJws = StringUtils.isNotBlank(this.jwsAlgo);
    if (doJws)
    {
      JsonWebSignature jws = new JsonWebSignature();
      jws.setAlgorithmHeaderValue(this.jwsAlgo);
      

      try
      {
        keyPersuasion = jws.getKeyPersuasion();
      }
      catch (JoseException e) {
        KeyPersuasion keyPersuasion;
        throw new IllegalStateException("Problem getting JWS key persuasion: " + e, e);
      }
      KeyPersuasion keyPersuasion;
      switch (keyPersuasion)
      {
      case ASYMMETRIC: 
        X500PrivateCredential signingKey = (X500PrivateCredential)this.signingKeys.get(this.activeCertKeyId);
        if (signingKey == null)
        {
          throw new IllegalStateException("The signing key for key id '" + this.activeCertKeyId + "' could not be found and is null.");
        }
        
        jws.setKey(signingKey.getPrivateKey());
        conditionallySetKeyIdHeader(jws, this.activeCertKeyId, this.includeJwsKid);
        setHeaderIfValueNotBlank(jws, "x5t", this.x5t);
        break;
      case SYMMETRIC: 
        Key macKey = (Key)this.symmetricKeys.get(this.activeMacKeyId);
        jws.setKey(macKey);
        conditionallySetKeyIdHeader(jws, this.activeMacKeyId, this.includeJwsKid);
        break;
      default: 
        throw newISE(jws, keyPersuasion);
      }
      
      jws.setPayload(payload);
      
      try
      {
        token = jws.getCompactSerialization();
        payload = token;
      }
      catch (JoseException e)
      {
        throw new IllegalStateException("Unable to create signed token: " + e, e);
      }
    }
    
    boolean hasSymmetricEnc = false;
    if (StringUtils.isNotBlank(this.jweAlgo))
    {
      JsonWebEncryption jwe = new JsonWebEncryption();
      jwe.setPayload(payload);
      jwe.setAlgorithmHeaderValue(this.jweAlgo);
      jwe.setEncryptionMethodHeaderParameter(this.jweEncAlgo);
      if (doJws)
      {
        jwe.setContentTypeHeaderValue("JWT");
      }
      

      try
      {
        keyPersuasion = jwe.getAlgorithm().getKeyPersuasion();
      }
      catch (JoseException e) {
        KeyPersuasion keyPersuasion;
        throw new IllegalStateException("Problem getting JWE key persuasion: " + e, e);
      }
      KeyPersuasion keyPersuasion;
      switch (keyPersuasion)
      {
      case SYMMETRIC: 
        Key encKey = (Key)this.symmetricKeys.get(this.activeSymmetricEncryptionKeyId);
        conditionallySetKeyIdHeader(jwe, this.activeSymmetricEncryptionKeyId, this.includeJweKid);
        jwe.setKey(encKey);
        hasSymmetricEnc = true;
        break;
      case ASYMMETRIC: 
        PublicJsonWebKey encryptionJwk = this.asymmetricEncryptionJwk;
        if (this.remoteJwksSupport != null)
        {
          encryptionJwk = this.remoteJwksSupport.getEncryptionKeyFor(jwe);
        }
        
        jwe.setKey(encryptionJwk.getPublicKey());
        conditionallySetKeyIdHeader(jwe, encryptionJwk.getKeyId(), this.includeJweKid);
        if (this.includeJweX5t)
        {
          String thumb = encryptionJwk.getX509CertificateSha1Thumbprint(true);
          if (thumb != null)
          {
            jwe.setX509CertSha1ThumbprintHeaderValue(thumb); }
        }
        break;
      
      default: 
        throw newISE(jwe, keyPersuasion);
      }
      
      try
      {
        token = jwe.getCompactSerialization();
      }
      catch (JoseException e)
      {
        throw new IllegalStateException("Unable to create encrypted token: " + e, e);
      }
    }
    
    if (token == null)
    {
      throw new IllegalStateException("cannot issue a token when not signed or encrypted");
    }
    
    if ((!doJws) && (!hasSymmetricEnc))
    {
      throw new IllegalStateException("cannot issue a token without some kind of integrity protection");
    }
    
    return new IssuedAccessToken(token, "Bearer", Long.valueOf(expiresAt.getValueInMillis()));
  }
  

  private NumericDate getExpiresAt(Map<String, AttributeValue> attributes)
  {
    int expTimeInAttributeFulfillment = getExpTimeInAttrFulfillmentMapping(attributes);
    NumericDate expiresAt;
    NumericDate expiresAt; if (expTimeInAttributeFulfillment != 0)
    {
      expiresAt = computeExpiresAt(expTimeInAttributeFulfillment);
    }
    else
    {
      expiresAt = computeExpiresAt(this.tokenLife);
    }
    
    return expiresAt;
  }
  
  private int getExpTimeInAttrFulfillmentMapping(Map<String, AttributeValue> attributes)
  {
    int expTimeInAttributeFulfillment = 0;
    
    if ((attributes != null) && (attributes.containsKey("exp")))
    {
      AttributeValue expTimeAttrValue = (AttributeValue)attributes.get("exp");
      if (ValidationUtil.isValidInt(expTimeAttrValue.getValue(), 1))
      {
        expTimeInAttributeFulfillment = Integer.parseInt(expTimeAttrValue.getValue());
      }
      else
      {
        log.debug("Invalid exp claim value in attribute contract fulfillment mapping: " + expTimeAttrValue.getValue());
      }
    }
    
    return expTimeInAttributeFulfillment;
  }
  
  private void addToPayload(Map<String, Object> payload, String name, Object value)
  {
    Object previousValue = payload.put(name, value);
    if (previousValue != null)
    {
      log.debug("Previous value for claim/attribute named " + name + " was " + previousValue + " and was replaced with " + value + " (might there be a name conflict?)");
    }
  }
  

  private IllegalStateException newISE(JsonWebStructure jwx, KeyPersuasion keyPersuasion)
  {
    return new IllegalStateException("Unknown or unsupported key persuasion: " + keyPersuasion + " for JOSE algorithm " + jwx
      .getAlgorithmHeaderValue());
  }
  
  private void setHeaderIfValueNotBlank(JsonWebSignature jws, String name, String value)
  {
    if (StringUtils.isNotBlank(value))
    {
      jws.setHeader(name, value);
    }
  }
  
  private void conditionallySetKeyIdHeader(JsonWebStructure jwx, String kid, boolean includeIt)
  {
    if ((includeIt) && (kid != null))
    {
      jwx.setKeyIdHeaderValue(kid);
    }
  }
  
  private void addIfNameNotBlankAndValueNotNull(Map<String, Object> payloadMap, String name, Object value)
  {
    if ((StringUtils.isNotBlank(name)) && (value != null))
    {
      addToPayload(payloadMap, name, value);
    }
  }
  
  private void addIfValueNotBlank(Map<String, Object> payloadMap, String name, String value)
  {
    if (StringUtils.isNotBlank(value))
    {
      addToPayload(payloadMap, name, value);
    }
  }
  

  public AccessToken validateAccessToken(String accessTokenValue)
  {
    try
    {
      return validateAT(accessTokenValue);
    }
    catch (InvalidTokenException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug(accessTokenValue + " is not valid: " + ExceptionUtil.toStringWithCauses(e));
      }
    }
    catch (JoseException e)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Problem in access token validation " + accessTokenValue + " " + ExceptionUtil.toStringWithCauses(e));
      }
    }
    catch (RuntimeException e)
    {
      log.warn("Unexpected problem in access token validation " + accessTokenValue, e);
    }
    return null;
  }
  
  static <T> T removeAndCheckClaim(String name, Map<String, Object> claims, Class<T> valueType, boolean isRequired, boolean enforceType)
    throws InvalidTokenException
  {
    Object objValue = claims.remove(name);
    
    if (objValue == null)
    {
      if (isRequired)
      {
        throw new InvalidTokenException(name + " is a required claim.");
      }
      

      return null;
    }
    

    if (valueType.isInstance(objValue))
    {
      return (T)valueType.cast(objValue);
    }
    

    if (enforceType)
    {

      String msg = "The value for " + name + " claim is the wrong type. Expected " + valueType + " but was " + objValue.getClass();
      throw new InvalidTokenException(msg);
    }
    

    return null;
  }
  

  private AccessToken validateAT(String accessTokenValue)
    throws InvalidTokenException, JoseException
  {
    JsonWebStructure jsonWebStructure = JsonWebStructure.fromCompactSerialization(accessTokenValue);
    JsonWebSignature jws = null;
    JsonWebEncryption jwe = null;
    String payloadString = null;
    
    if ((jsonWebStructure instanceof JsonWebEncryption))
    {
      jwe = (JsonWebEncryption)jsonWebStructure;
    }
    else
    {
      jws = (JsonWebSignature)jsonWebStructure;
    }
    
    if (jwe != null)
    {
      if (log.isDebugEnabled())
      {
        log.debug("JWE: " + jwe.getHeaders().getFullHeaderAsJsonString());
      }
      KeyPersuasion keyPersuasion = jwe.getAlgorithm().getKeyPersuasion();
      switch (keyPersuasion)
      {

      case SYMMETRIC: 
        String kid = jwe.getKeyIdHeaderValue();
        Key key = chooseSymmetricKeyForDecryption(kid);
        if (key == null)
        {
          throw new InvalidTokenException("Unable to locate a symmetric key for decrypting token with Key ID '" + kid + "'");
        }
        jwe.setKey(key);
        break;
      case ASYMMETRIC: 
        throw new InvalidTokenException("Unable to locally decrypt tokens using asymmetric encryption (" + jwe.getAlgorithmHeaderValue() + ").");
      default: 
        throw newISE(jws, keyPersuasion);
      }
      
      String cty = jwe.getContentTypeHeaderValue();
      if ((cty != null) && ((cty.equalsIgnoreCase("jwt")) || (cty.equalsIgnoreCase("application/jwt"))))
      {
        jws = new JsonWebSignature();
        jws.setCompactSerialization(jwe.getPayload());
      }
      else
      {
        payloadString = jwe.getPayload();
      }
    }
    
    if (jws != null)
    {
      if (log.isDebugEnabled())
      {
        log.debug("JWS: " + jws.getHeaders().getFullHeaderAsJsonString() + "." + jws.getUnverifiedPayload());
      }
      
      KeyPersuasion keyPersuasion = jws.getKeyPersuasion();
      String kid = jws.getKeyIdHeaderValue();
      switch (keyPersuasion)
      {
      case ASYMMETRIC: 
        X509Certificate verificationCert = (X509Certificate)this.kidToCertMap.get(kid != null ? kid : this.activeCertKeyId);
        
        String x5t = jws.getHeader("x5t");
        if (x5t != null)
        {
          verificationCert = (X509Certificate)this.thumbToCertMap.get(x5t);
        }
        
        if (verificationCert != null)
        {
          jws.setKey(verificationCert.getPublicKey());
        }
        else
        {
          throw new InvalidTokenException("Unable to locate a verification key for token with Key ID '" + kid + "' and/or X509 Thumbprint '" + x5t + "'");
        }
        

        break;
      case SYMMETRIC: 
        Key macKey = chooseMacKeyForVerification(kid);
        if (macKey == null)
        {
          throw new InvalidTokenException("Unable to locate a symmetric verification key for token with Key ID '" + kid + "'");
        }
        jws.setKey(macKey);
        break;
      default: 
        throw newISE(jws, keyPersuasion);
      }
      
      if (!jws.verifySignature())
      {
        throw new InvalidTokenException("Invalid signature.");
      }
      
      payloadString = jws.getPayload();
    }
    
    if (payloadString == null)
    {
      throw new InvalidTokenException("Unable to get payload from token " + accessTokenValue);
    }
    
    Map<String, Object> payload = JsonUtil.parseJson(payloadString);
    
    String jwtIdValue = (String)removeAndCheckClaim("jti", payload, String.class, false, true);
    
    String mappedIssuer = null;
    if (payload.get("iss") != null)
    {
      mappedIssuer = (String)payload.get("iss");
    }
    validateClaim(payload, "iss", this.issuerValue, false);
    validateClaim(payload, "aud", this.audienceValue, false);
    
    Long exp = (Long)removeAndCheckClaim("exp", payload, Long.class, true, true);
    NumericDate expiresAt = NumericDate.fromSeconds(exp.longValue());
    
    String scopeString = null;
    if (StringUtils.isNotBlank(this.scopeClaimName))
    {
      Object scopeObj = payload.remove(this.scopeClaimName);
      if ((scopeObj instanceof Collection))
      {
        Collection<String> scopes = (Collection)scopeObj;
        Scope scope = new Scope((String[])scopes.toArray(new String[scopes.size()]));
        scopeString = scope.getScopeStr();
      }
      else if ((scopeObj instanceof String))
      {
        scopeString = (String)scopeObj;
      }
      else
      {
        log.debug("scope claim not a string or an array so ignoring value");
      }
    }
    
    String clientId = removeValue(payload, this.clientIdClaimName);
    String guid = removeValue(payload, this.accessGrantGuidClaimName);
    
    if (guid != null)
    {
      AccessGrant byGuid = this.accessGrantManager.getByGuid(guid);
      if (byGuid == null)
      {
        throw new InvalidTokenException("Revoked, expired or otherwise invalid/unknown access grant guid: " + guid);
      }
    }
    

    HashMap<String, AttributeValue> attrs = new HashMap();
    
    for (Map.Entry<String, Object> e : payload.entrySet())
    {
      Object v = e.getValue();
      AttributeValue value;
      AttributeValue value; if ((v instanceof Collection))
      {
        value = new AttributeValue((Collection)v);
      }
      else
      {
        value = AttrValueSupport.make(v);
      }
      
      attrs.put(e.getKey(), value);
    }
    
    AccessToken accessToken = new AccessToken(expiresAt.getValueInMillis(), attrs, scopeString, clientId, guid);
    if (StringUtils.isNotBlank(this.audienceValue))
    {
      accessToken.setAudience(Arrays.asList(this.audienceValue.split(" ")));
    }
    if (StringUtils.isNotBlank(this.issuerValue))
    {
      accessToken.setIssuer(this.issuerValue);
    }
    else if (StringUtils.isNotBlank(mappedIssuer))
    {
      accessToken.setIssuer(mappedIssuer);
    }
    accessToken.setTokenIdentifier(jwtIdValue);
    
    return accessToken;
  }
  
  public String removeValue(Map<String, Object> payload, String name) throws InvalidTokenException
  {
    if (StringUtils.isNotBlank(name))
    {
      return (String)removeAndCheckClaim(name, payload, String.class, false, true);
    }
    return null;
  }
  
  void validateClaim(Map<String, Object> payload, String name, String expectedvalue, boolean failIfReceivedButNotExpected)
    throws InvalidTokenException
  {
    Object value = payload.remove(name);
    if (StringUtils.isNotBlank(expectedvalue))
    {
      if ((!(value instanceof String)) || (!StringUtils.equals(expectedvalue, (String)value)))
      {
        throw new InvalidTokenException(name + " claim validation failed - expected " + expectedvalue + " but was " + value);
      }
      
    }
    else if ((failIfReceivedButNotExpected) && (value != null))
    {
      throw new InvalidTokenException(name + " claim validation failed - no claim expected but value was " + value);
    }
  }
  

  private Key chooseSymmetricKeyForDecryption(String kid)
  {
    return (Key)this.symmetricKeys.get(StringUtils.isNotBlank(kid) ? kid : this.activeSymmetricEncryptionKeyId);
  }
  
  private Key chooseMacKeyForVerification(String kid)
  {
    return (Key)this.symmetricKeys.get(StringUtils.isNotBlank(kid) ? kid : this.activeMacKeyId);
  }
  

  public void configure(Configuration configuration)
  {
    this.tokenLife = configuration.getIntFieldValue("Token Lifetime");
    
    this.jwsAlgo = configuration.getFieldValue("JWS Algorithm");
    
    this.signingKeys = new HashMap();
    
    configureCerts(configuration, this.kidToCertMap, this.thumbToCertMap, this.signingKeys);
    
    this.activeCertKeyId = configuration.getFieldValue("Active Signing Certificate Key ID");
    if (configuration.getBooleanFieldValue("Include X.509 Thumbprint Header Parameter"))
    {
      X509Certificate activeCert = (X509Certificate)this.kidToCertMap.get(this.activeCertKeyId);
      if (activeCert != null)
      {
        this.x5t = this.certSupport.calculateThumb(activeCert);
      }
    }
    
    Table symmetricKeys = configuration.getTable("Symmetric Keys");
    List<Row> keyRows = symmetricKeys.getRows();
    this.symmetricKeys = new HashMap(keyRows.size());
    for (Row keyRow : keyRows)
    {
      String kid = keyRow.getFieldValue("Key ID");
      Key key = SymmetricKeySupport.getKey(keyRow);
      this.symmetricKeys.put(kid, key);
    }
    
    this.activeMacKeyId = configuration.getFieldValue("Active Symmetric Key ID");
    
    this.includeJwsKid = configuration.getBooleanFieldValue("Include Key ID Header Parameter");
    
    this.clientIdClaimName = configuration.getFieldValue("Client ID Claim Name");
    this.scopeClaimName = configuration.getFieldValue("Scope Claim Name");
    this.accessGrantGuidClaimName = configuration.getFieldValue("Access Grant GUID Claim Name");
    
    this.spaceDelimitScope = configuration.getBooleanFieldValue("Space Delimit Scope Values");
    
    this.jwtIdClaimLength = configuration.getIntFieldValue("JWT ID Claim Length");
    
    this.issuerValue = configuration.getFieldValue("Issuer Claim Value");
    this.audienceValue = configuration.getFieldValue("Audience Claim Value");
    
    this.jweAlgo = configuration.getFieldValue("JWE Algorithm");
    this.jweEncAlgo = configuration.getFieldValue("JWE Content Encryption Algorithm");
    this.activeSymmetricEncryptionKeyId = configuration.getFieldValue("Active Symmetric Encryption Key ID");
    org.sourceid.saml20.adapter.conf.Field asymmetricKeyField = configuration.getField("Asymmetric Encryption Key");
    this.asymmetricEncryptionJwk = PublicJwkSupport.getKey(asymmetricKeyField);
    String jwksUrl = configuration.getFieldValue("Asymmetric Encryption JWKS URL");
    if (StringUtils.isNotBlank(jwksUrl))
    {
      long defaultCacheDuration = configuration.getLongFieldValue("Default JWKS URL Cache Duration");
      this.remoteJwksSupport = new RemoteJwksSupport(jwksUrl, defaultCacheDuration);
    }
    
    this.includeJweKid = configuration.getBooleanFieldValue("Include JWE Key ID Header Parameter");
    this.includeJweX5t = configuration.getBooleanFieldValue("Include JWE X.509 Thumbprint Header Parameter");
    
    setUpHandlers(configuration);
  }
  
  public void setUpHandlers(Configuration configuration)
  {
    Map<String, X509Certificate> newKidToCertMap = new HashMap();
    Map<String, X509Certificate> newThumbToCertMap = new HashMap();
    
    MutableBoolean onePublishesByKid = new MutableBoolean(false);
    MutableBoolean onePublishesByThumb = new MutableBoolean(false);
    
    for (BearerAccessTokenMgmtPluginInstance instance : this.tokenPluginManager.getInstances())
    {
      if ((!instance.getId().equals(configuration.getId())) && (instance.getDescriptor().getPluginClassName().equals(getClass().getName())))
      {
        checkPublishCerts(instance.getCompositeConfiguration(), null, null, newKidToCertMap, newThumbToCertMap, onePublishesByKid, onePublishesByThumb);
      }
    }
    
    checkPublishCerts(configuration, this.kidToCertMap, this.thumbToCertMap, newKidToCertMap, newThumbToCertMap, onePublishesByKid, onePublishesByThumb);
    
    setUpHandler(onePublishesByKid.booleanValue(), "/oauth/x509/kid", new X509CertificateEndpointHandler("Key ID", newKidToCertMap));
    setUpHandler(onePublishesByThumb.booleanValue(), "/oauth/x509/x5t", new X509CertificateEndpointHandler("X.509 Thumbprint", newThumbToCertMap));
    
    String jwksPath = configuration.getFieldValue("JWKS Endpoint Path");
    if (StringUtils.isNotBlank(jwksPath))
    {
      List<JsonWebKey> jwks = new ArrayList();
      
      for (Map.Entry<String, X509Certificate> entry : this.kidToCertMap.entrySet())
      {
        X509Certificate x5 = (X509Certificate)entry.getValue();
        String kid = (String)entry.getKey();
        
        try
        {
          PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(x5.getPublicKey());
          jwk.setKeyId(kid);
          jwk.setUse("sig");
          jwk.setCertificateChain(new X509Certificate[] { x5 });
          jwk.setX509CertificateSha1Thumbprint(X509Util.x5t(x5));
          jwks.add(jwk);

        }
        catch (JoseException je)
        {
          log.error("Unable to add certificate with kid " + kid + " to JWKS: " + je, je);
        }
      }
      
      int maxAgeMinutes = configuration.getIntFieldValue("JWKS Endpoint Cache Duration");
      
      HandlerRegistry.registerHandler(jwksPath, new JwksEndpointHandler(jwks, maxAgeMinutes * 60));
    }
  }
  


  private void checkPublishCerts(Configuration configuration, Map<String, X509Certificate> aKidToCertMap, Map<String, X509Certificate> aThumbToCertMap, Map<String, X509Certificate> publishKidToCertMap, Map<String, X509Certificate> publishThumbToCertMap, MutableBoolean onePublishesByKid, MutableBoolean onePublishesByThumb)
  {
    boolean registerKid = configuration.getBooleanFieldValue("Publish Key ID X.509 URL");
    boolean registerThumb = configuration.getBooleanFieldValue("Publish Thumbprint X.509 URL");
    
    onePublishesByKid.setValue((onePublishesByKid.booleanValue()) || (registerKid));
    onePublishesByThumb.setValue((onePublishesByThumb.booleanValue()) || (registerThumb));
    
    if ((registerKid) || (registerThumb))
    {
      if ((aKidToCertMap == null) || (aThumbToCertMap == null))
      {
        aKidToCertMap = new HashMap();
        aThumbToCertMap = new HashMap();
        configureCerts(configuration, aKidToCertMap, aThumbToCertMap, new HashMap());
      }
    }
    if (registerKid)
    {
      for (Map.Entry<String, X509Certificate> entry : aKidToCertMap.entrySet())
      {
        if ((publishKidToCertMap.containsKey(entry.getKey())) && (!((X509Certificate)entry.getValue()).equals(publishKidToCertMap.get(entry.getKey()))))
        {
          log.error("Different certificates are published with the same key ID '" + (String)entry.getKey() + "', please ensure instances of the JSON Web Tokens access token manager use distinct IDs for their certificates");

        }
        else
        {
          publishKidToCertMap.put(entry.getKey(), entry.getValue());
        }
      }
    }
    if (registerThumb)
    {
      publishThumbToCertMap.putAll(aThumbToCertMap);
    }
  }
  
  private void configureCerts(Configuration configuration, Map<String, X509Certificate> aKidToCertMap, Map<String, X509Certificate> aThumbToCertMap, Map<String, X500PrivateCredential> aSigningKeysMap)
  {
    Table certs = configuration.getTable("Certificates");
    List<Row> rows = certs.getRows();
    for (Row row : rows)
    {
      String kid = row.getFieldValue("Key ID");
      String alias = row.getFieldValue("Certificate");
      X500PrivateCredential x500 = this.certSupport.getDsigKeypair(alias);
      if (x500 != null)
      {
        aSigningKeysMap.put(kid, x500);
        X509Certificate x509Certificate = x500.getCertificate();
        String thumb = this.certSupport.calculateThumb(x509Certificate);
        aThumbToCertMap.put(thumb, x509Certificate);
        aKidToCertMap.put(kid, x509Certificate);
      }
      else
      {
        log.warn("Unable to find certificate and keypair for alias " + alias);
      }
    }
  }
  

  private void setUpHandler(boolean register, String path, X509CertificateEndpointHandler handler)
  {
    HandlerRegistry.registerHandler(path, register ? handler : null);
  }
  
  private NumericDate computeExpiresAt(int tokenLifeInMinutes)
  {
    NumericDate exp = NumericDate.now();
    exp.addSeconds(tokenLifeInMinutes * 60);
    return exp;
  }
  

  public PluginDescriptor getPluginDescriptor()
  {
    return this.pluginDescriptor;
  }
  
  AccessGrantManager getAccessGrantManager()
  {
    return this.accessGrantManager;
  }
  

  private static class HackGuiConfigDescriptor
    extends GuiConfigDescriptor
  {
    public Set<Class<? extends FieldDescriptor>> getAllDescriptorTypesInUse()
    {
      Set<Class<? extends FieldDescriptor>> typesInUse = super.getAllDescriptorTypesInUse();
      typesInUse.add(org.sourceid.saml20.adapter.gui.DsigKeypairFieldDescriptor.class);
      return typesInUse;
    }
  }
  
  String getVersion()
  {
    return org.sourceid.common.VersionUtil.getVersion();
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\access\token\management\plugins\JwtBearerAccessTokenManagementPlugin.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */