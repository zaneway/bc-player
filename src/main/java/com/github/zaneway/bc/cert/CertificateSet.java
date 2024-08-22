package com.github.zaneway.bc.cert;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x509.Certificate;

/**
 *  CertificateSet ::= SET OF CertificateChoices
 */
public class CertificateSet extends ASN1Object {

    private ASN1Set certificateSet;

    public static CertificateSet getInstance(Object o) {
      if (o instanceof CertificateSet) {
        return (CertificateSet) o;
      }else if (o !=null) {
        return new CertificateSet(ASN1Set.getInstance(o));
      }
      return null;
    }

    private CertificateSet(ASN1Set certificateSet) {
      this.certificateSet = certificateSet;
    }

    public List<Certificate> getCertificate() {
      ArrayList<Certificate> certificates = new ArrayList<>();
      Enumeration objects = certificateSet.getObjects();
      while (objects.hasMoreElements()){
        certificates.add(Certificate.getInstance(objects.nextElement()));
      }
      return certificates;
    }


  @Override
  public ASN1Primitive toASN1Primitive() {
    return certificateSet;
  }
}
