package com.github.zaneway.bc.cert.extend;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class ExtendedCertificate extends ASN1Object {

  private ExtendedCertificateInfo extendedCertificateInfo;

  private AlgorithmIdentifier signatureAlgorithm;

  private ASN1BitString signature;

  public static ExtendedCertificate getInstance(Object object) {
    if (object instanceof ExtendedCertificate) {
      return (ExtendedCertificate) object;
    } else if (object != null) {
      return new ExtendedCertificate((ASN1Sequence) object);
    }
    return null;
  }


  private ExtendedCertificate(ASN1Sequence sequence) {
    this.extendedCertificateInfo = ExtendedCertificateInfo.getInstance(sequence.getObjectAt(0));
    this.signatureAlgorithm = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
    this.signature = ASN1BitString.getInstance(sequence.getObjectAt(2));
  }


  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    vector.add(extendedCertificateInfo);
    vector.add(signatureAlgorithm);
    vector.add(signature);
    return new DERSequence(vector);
  }
}
