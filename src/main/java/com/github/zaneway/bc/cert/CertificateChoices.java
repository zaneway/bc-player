package com.github.zaneway.bc.cert;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.oer.its.etsi102941.basetypes.CertificateFormat;

/**
 * CertificateChoices ::= CHOICE {
 *    certificate Certificate,
 *    extendedCertificate [0] IMPLICIT   ExtendedCertificate, -- Obsolete
 *    v1AttrCert [1] IMPLICIT  AttributeCertificateV1,  Obsolete
 *    v2AttrCert [2] IMPLICIT  AttributeCertificateV2,
 *    other [3] IMPLICIT  OtherCertificateFormat
 *    }
 */
public class CertificateChoices extends ASN1Object {
  private ASN1Encodable choice;

  private CertificateChoices(ASN1TaggedObject taggedObject) {
    switch (taggedObject.getTagNo()) {
      case 0:
        throw new UnsupportedOperationException("ExtendedCertificate is deprecated");
      case 1:
        throw new UnsupportedOperationException("AttributeCertificateV1 is deprecated");
      case 2:
        this.choice = AttributeCertificate.getInstance(taggedObject);
        break;
      case 3:
        this.choice = CertificateFormat.getInstance(taggedObject);
        break;
      default:
        throw new IllegalArgumentException("Invalid tag number: " + taggedObject.getTagNo());
    }
  }


  private CertificateChoices(Certificate certificate) {
    this.choice = certificate;
  }

  public static CertificateChoices getInstance(Object obj) {
    if (obj instanceof CertificateChoices) {
      return (CertificateChoices) obj;
    } else if (obj instanceof ASN1Primitive) {
      return new CertificateChoices(ASN1TaggedObject.getInstance(obj));
    } else if (obj instanceof Certificate) {
      return new CertificateChoices((Certificate) obj);
    } else if (obj instanceof ASN1TaggedObject) {
      return new CertificateChoices((ASN1TaggedObject) obj);
    }
    throw new IllegalArgumentException("Invalid object: " + obj.getClass().getName());
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    if (choice instanceof Certificate) {
      return ((Certificate) choice).toASN1Primitive();
    } else if (choice instanceof ASN1TaggedObject) {
      return ((ASN1TaggedObject) choice).toASN1Primitive();
    } else {
      // Handle other types as needed
      return choice.toASN1Primitive();
    }
  }
}
