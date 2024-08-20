package com.github.zaneway.bc.cert.extend;

import com.github.zaneway.bc.attribute.UnauthAttribute;
import com.github.zaneway.bc.cert.ESMSVersion;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Certificate;

public class ExtendedCertificateInfo extends ASN1Object {

  private ESMSVersion version;

  private Certificate certificate;

  private UnauthAttribute attribute;

  public static ExtendedCertificateInfo getInstance(Object object){
    if (object instanceof ExtendedCertificateInfo){
      return (ExtendedCertificateInfo)object;
    }else if (object instanceof ASN1Sequence){
      return new ExtendedCertificateInfo((ASN1Sequence)object);
    }
    return null;
  }


  private ExtendedCertificateInfo(ASN1Sequence sequence) {
    this.version = ESMSVersion.getInstance(sequence.getObjectAt(0));
    this.certificate = Certificate.getInstance(sequence.getObjectAt(1));
    this.attribute = UnauthAttribute.getInstance(sequence.getObjectAt(2));
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    vector.add(version);
    vector.add(certificate);
    vector.add(attribute);
    return new DERSequence(vector);
  }
}
