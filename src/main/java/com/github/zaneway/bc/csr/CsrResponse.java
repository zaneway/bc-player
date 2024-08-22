package com.github.zaneway.bc.csr;

import com.github.zaneway.bc.cert.CertificateSet;
import com.github.zaneway.bc.sm2.SM2EnvelopedKey;
import java.util.List;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Certificate;

public class CsrResponse extends ASN1Object {

  private CertificateSet certificateSet;
  private ASN1TaggedObject encryptedPrivateKey;
  private ASN1TaggedObject encryptedCertificate;

  public static CsrResponse getInstance(Object object) {
    if (object instanceof CsrResponse) {
      return (CsrResponse) object;
    } else if (object != null) {
      return new CsrResponse(ASN1Sequence.getInstance(object));
    }
    return null;
  }

  private CsrResponse(ASN1Sequence sequence) {
    this.certificateSet = CertificateSet.getInstance(sequence.getObjectAt(0));
    this.encryptedPrivateKey = ASN1TaggedObject.getInstance(sequence.getObjectAt(1));
    this.encryptedCertificate = ASN1TaggedObject.getInstance(sequence.getObjectAt(2));
  }


  public List<Certificate> getCertificateSet() {
    return certificateSet.getCertificate();
  }

  public SM2EnvelopedKey getSm2EnvelopedKey() {
    return SM2EnvelopedKey.getInstance(encryptedPrivateKey.getBaseObject());
  }


  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    vector.add(certificateSet);
    vector.add(encryptedPrivateKey);
    vector.add(encryptedCertificate);
    return new DERSequence(vector);
  }
}
