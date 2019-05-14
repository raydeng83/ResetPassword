package com.pingidentity.pf.selectors.http;

import com.pingidentity.sdk.AuthenticationSelector;
import com.pingidentity.sdk.AuthenticationSelectorContext;
import com.pingidentity.sdk.AuthenticationSelectorContext.ResultType;
import com.pingidentity.sdk.AuthenticationSelectorDescriptor;
import com.pingidentity.sdk.AuthenticationSourceKey;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.common.Util;
import org.sourceid.common.VersionUtil;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.TableDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.FieldValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;


public class HTTPHeaderAdapterSelector
  implements AuthenticationSelector
{
  private final Log log = LogFactory.getLog(HTTPHeaderAdapterSelector.class);
  private final AuthenticationSelectorDescriptor authnSelectorDescriptor;
  private String headerName = null;
  List<String> expressions = new ArrayList();
  private boolean enableCaseSensitiveMatch = true;
  
  public static final String RESULT_YES = "Yes";
  
  public static final String RESULT_NO = "No";
  
  protected static final String RESULTS_TABLE_NAME = "Results";
  
  protected static final String MATCH_EXPR_FIELD_NAME = "Match Expression";
  
  protected static final String HTTP_HEADER_NAME_FIELD_NAME = "Header Name";
  
  private static final String FIELD_ENABLE_CASESENSITIVE = "Case-Sensitive Matching";
  private static final String DESCRIPTION = "This authentication selector provides a means of choosing authentication sources at runtime based on HTTP headers.";
  private static final String DESC_ENABLE_CASESENSITIVE = "Allows case-sensitive expression matching to HTTP header.";
  private static final boolean DEFAULT_VALUE_ENABLE_CASESENSITIVE = true;
  private static final String INVALID_HTTP_HEADER_NAME_CHARS = "( ) < > @ , ; : \\ \" / [ ] ? = { } space tab";
  private static final String SEPARATORS = "\\(\\)\\<\\>@,;:\\\\\"/\\[\\]\\?=\\{\\}";
  private static final String SP = "\\u0020";
  private static final String CTL = "\\u0000-\\u001F\\u007F";
  private static final String INVALID_HTTP_HEADER_NAME_CHARS_REGEX = String.format(".*[%s%s%s]+.*", new Object[] { "\\(\\)\\<\\>@,;:\\\\\"/\\[\\]\\?=\\{\\}", "\\u0020", "\\u0000-\\u001F\\u007F" });
  


  public HTTPHeaderAdapterSelector()
  {
    GuiConfigDescriptor guiConfigDescriptor = new GuiConfigDescriptor();
    guiConfigDescriptor.setDescription("This authentication selector provides a means of choosing authentication sources at runtime based on HTTP headers.");
    
    TableDescriptor matchesTable = new TableDescriptor("Results", "A table of expressions to match against the values for the given header name.  If any expression matches, the result value is Yes.");
    


    FieldDescriptor matchExpressionField = new TextFieldDescriptor("Match Expression", "The expression matched against the specified header.");
    
    matchExpressionField.addValidator(new RequiredFieldValidator());
    matchExpressionField.addValidator(new FieldValidator()
    {
      private static final long serialVersionUID = 1L;
      
      public void validate(Field field)
        throws ValidationException
      {
        try
        {
          Util.wildCardMatch("", field.getValue(), true);
        }
        catch (PatternSyntaxException ex)
        {
          throw new ValidationException("Invalid match expression " + field.getValue());
        }
        
      }
    });
    FieldDescriptor headerNameField = new TextFieldDescriptor("Header Name", "HTTP header to inspect for a match.");
    
    headerNameField.addValidator(new RequiredFieldValidator());
    headerNameField.addValidator(new FieldValidator()
    {
      private static final long serialVersionUID = 1L;
      
      public void validate(Field field)
        throws ValidationException
      {
        try
        {
          Pattern pattern = Pattern.compile(HTTPHeaderAdapterSelector.INVALID_HTTP_HEADER_NAME_CHARS_REGEX);
          Matcher matcher = pattern.matcher(field.getValue());
          if (matcher.matches())
          {
            throw new ValidationException("HTTP header name field contains one or more invalid characters.  Invalid characters are ( ) < > @ , ; : \\ \" / [ ] ? = { } space tab");
          }
          

        }
        catch (PatternSyntaxException ex)
        {
          throw new ValidationException("Invalid regular expression " + HTTPHeaderAdapterSelector.INVALID_HTTP_HEADER_NAME_CHARS_REGEX);
        }
        
      }
    });
    matchesTable.addRowField(matchExpressionField);
    
    guiConfigDescriptor.addTable(matchesTable);
    guiConfigDescriptor.addField(headerNameField);
    
    CheckBoxFieldDescriptor enableCaseSensitiveField = new CheckBoxFieldDescriptor("Case-Sensitive Matching", "Allows case-sensitive expression matching to HTTP header.");
    enableCaseSensitiveField.setDefaultValue(true);
    enableCaseSensitiveField.setDefaultForLegacyConfig(Boolean.toString(true));
    
    guiConfigDescriptor.addField(enableCaseSensitiveField);
    
    guiConfigDescriptor.addValidator(new ConfigurationValidator()
    {
      public void validate(Configuration configuration)
        throws ValidationException
      {
        Table table = configuration.getTable("Results");
        boolean caseSensitiveMatch = true;
        Field caseSensitiveField = configuration.getField("Case-Sensitive Matching");
        if (caseSensitiveField != null)
        {
          caseSensitiveMatch = caseSensitiveField.getValueAsBoolean();
        }
        
        List<Row> rows = table.getRows();
        if (rows.isEmpty())
        {
          throw new ValidationException("Please add at least one match expression to the 'Results' table.");
        }
        
        List<String> errors = new ArrayList();
        Set<String> expressions = new HashSet();
        for (Row row : rows)
        {
          String expression = row.getFieldValue("Match Expression");
          if (!caseSensitiveMatch)
          {
            expression = expression.toLowerCase();
          }
          
          if (!expressions.add(expression))
          {
            errors.add("Duplicate expression: '" + row.getFieldValue("Match Expression") + "'.");
          }
        }
        
        if (!errors.isEmpty())
        {
          throw new ValidationException(errors);
        }
        
      }
    });
    Set<String> results = new HashSet();
    results.add("Yes");
    results.add("No");
    
    this.authnSelectorDescriptor = new AuthenticationSelectorDescriptor("HTTP Header Authentication Selector", this, guiConfigDescriptor, results, getVersion());
    this.authnSelectorDescriptor.setSupportsExtendedResults(false);
  }
  

  public void configure(Configuration configuration)
  {
    this.headerName = configuration.getFieldValue("Header Name");
    
    Table matchTable = configuration.getTable("Results");
    
    if ((matchTable != null) && (matchTable.getRows() != null))
    {
      for (Row matchRow : matchTable.getRows())
      {
        String expr = matchRow.getFieldValue("Match Expression");
        if (StringUtils.isNotEmpty(expr))
        {
          this.expressions.add(expr);
        }
      }
    }
    
    Field caseSensitiveField = configuration.getField("Case-Sensitive Matching");
    if (caseSensitiveField != null)
    {
      this.enableCaseSensitiveMatch = caseSensitiveField.getValueAsBoolean();
    }
  }
  

  public PluginDescriptor getPluginDescriptor()
  {
    return this.authnSelectorDescriptor;
  }
  



  public AuthenticationSelectorContext selectContext(HttpServletRequest req, HttpServletResponse res, Map<AuthenticationSourceKey, String> mappedAuthnSourcesNames, Map<String, Object> extraParameters, String resumePath)
  {
    AuthenticationSelectorContext context = new AuthenticationSelectorContext();
    context.setResultType(AuthenticationSelectorContext.ResultType.CONTEXT);
    context.setResult("No");
    

    Enumeration<String> headerValuesEnumeration = req.getHeaders(this.headerName);
    Collection<String> headerValuesCollection = Collections.list(headerValuesEnumeration);
    
    if (Util.isEmpty(headerValuesCollection))
    {
      this.log.debug("HTTP header " + this.headerName + " does not exist.");
      return context;
    }
    for (Iterator localIterator1 = this.expressions.iterator(); localIterator1.hasNext();) { expression = (String)localIterator1.next();
      
      for (String headerValue : headerValuesCollection)
      {
        boolean match = Util.wildCardMatch(headerValue, expression, this.enableCaseSensitiveMatch);
        if (match)
        {
          this.log.debug(expression + " matches " + headerValue + ".");
          context.setResult("Yes");
          return context;
        }
        

        this.log.debug(expression + " does not match " + headerValue + ".");
      }
    }
    
    String expression;
    return context;
  }
  


  public void callback(HttpServletRequest req, HttpServletResponse res, Map authnIdentifiers, AuthenticationSourceKey authenticationSourceKey, AuthenticationSelectorContext authnSelectorContext) {}
  


  String getVersion()
  {
    return VersionUtil.getVersion();
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\selectors\http\HTTPHeaderAdapterSelector.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */