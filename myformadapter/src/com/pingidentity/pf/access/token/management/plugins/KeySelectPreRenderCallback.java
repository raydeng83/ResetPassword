package com.pingidentity.pf.access.token.management.plugins;

import java.util.ArrayList;
import java.util.List;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.gui.AbstractSelectionFieldDescriptor.OptionValue;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.SelectFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TableDescriptor;
import org.sourceid.saml20.adapter.gui.event.PreRenderCallback;



public class KeySelectPreRenderCallback
  implements PreRenderCallback
{
  String tableName;
  SelectFieldDescriptor field;
  
  public KeySelectPreRenderCallback(String tableName, SelectFieldDescriptor field)
  {
    this.tableName = tableName;
    this.field = field;
  }
  


  public void callback(List<FieldDescriptor> fields, List<FieldDescriptor> advancedFields, List<TableDescriptor> tables, Configuration config)
  {
    Table keys = config.getTable(this.tableName);
    if (keys != null)
    {
      List<AbstractSelectionFieldDescriptor.OptionValue> options = new ArrayList();
      options.add(SelectFieldDescriptor.SELECT_ONE);
      for (Row r : keys.getRows())
      {
        String kid = r.getFieldValue("Key ID");
        options.add(new AbstractSelectionFieldDescriptor.OptionValue(kid, kid));
      }
      this.field.setOptionValues(options);
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\access\token\management\plugins\KeySelectPreRenderCallback.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */