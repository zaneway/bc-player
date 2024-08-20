package com.github.zaneway.bc.cert;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * from GB/T-31503 12.2.5
 */
public class ESMSVersion extends ASN1Object {

  // 0-5
  private int version;

  public static ESMSVersion getInstance(Object o) {
    if (o instanceof ESMSVersion) {
      return (ESMSVersion) o;
    } else if (o instanceof Integer) {
      return new ESMSVersion((Integer) o);
    }
    return null;
  }

  private ESMSVersion(int version) {
    this.version = version;
  }


  @Override
  public ASN1Primitive toASN1Primitive() {
    return ASN1Integer.getInstance(version);
  }
}
