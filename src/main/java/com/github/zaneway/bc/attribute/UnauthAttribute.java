package com.github.zaneway.bc.attribute;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.Attributes;

public class UnauthAttribute extends ASN1Object {

  private ASN1Set attributes;

  public static UnauthAttribute getInstance(Object obj)
  {
    if (obj instanceof Attributes)
    {
      return (UnauthAttribute)obj;
    }
    else if (obj != null)
    {
      return new UnauthAttribute(ASN1Set.getInstance(obj));
    }

    return null;
  }

  private UnauthAttribute(ASN1Set attributes) {
    this.attributes = attributes;
  }

  public Attribute[] getAttributes()
  {
    Attribute[] rv = new Attribute[attributes.size()];

    for (int i = 0; i != rv.length; i++)
    {
      rv[i] = Attribute.getInstance(attributes.getObjectAt(i));
    }

    return rv;
  }


  @Override
  public ASN1Primitive toASN1Primitive() {
    return attributes;
  }
}
