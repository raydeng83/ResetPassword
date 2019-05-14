package com.pingidentity.provisioner.saas.scim11serviceprovider;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.introspect.JacksonAnnotationIntrospector;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationIntrospector;
import javax.ws.rs.Produces;
import javax.ws.rs.ext.ContextResolver;
import javax.ws.rs.ext.Provider;





@Provider
@Produces({"application/json"})
public class Scim11ContextProvider
  implements ContextResolver<ObjectMapper>
{
  final ObjectMapper mapper;
  
  public Scim11ContextProvider()
  {
    ObjectMapper objMapper = new ObjectMapper();
    

    AnnotationIntrospector intr = AnnotationIntrospector.pair(new JacksonAnnotationIntrospector(), new JaxbAnnotationIntrospector(TypeFactory.defaultInstance()));
    
    objMapper.setAnnotationIntrospector(intr);
    objMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    objMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    
    objMapper.registerModule(new Scim11JacksonModule());
    
    objMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    



    this.mapper = objMapper;
  }
  

  public ObjectMapper getContext(Class<?> arg0)
  {
    return this.mapper;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\provisioner\saas\scim11serviceprovider\Scim11ContextProvider.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */