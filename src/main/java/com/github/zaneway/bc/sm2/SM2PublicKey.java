package com.github.zaneway.bc.sm2;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

public class SM2PublicKey extends ASN1Object {
  // 04||x||y
  private ASN1BitString publicKey;

  public static SM2PublicKey getInstance(Object o) {
    if (o instanceof SM2PublicKey) {
      return (SM2PublicKey) o;
    } else if (o != null) {
      return new SM2PublicKey(ASN1BitString.getInstance(o));
    }
    return null;
  }

  private SM2PublicKey(ASN1BitString publicKey) {
    this.publicKey = publicKey;
  }


  @Override
  public ASN1Primitive toASN1Primitive() {
    return publicKey;
  }
}
