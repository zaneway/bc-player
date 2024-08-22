package com.github.zaneway.bc.sm2;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class SM2EnvelopedKey extends ASN1Object {

  private AlgorithmIdentifier symAlgID;
  private SM2Cipher symEncryptedKey;
  private SM2PublicKey sm2PublicKey;
  private ASN1BitString sm2EncryptedPrivateKey;

  public static SM2EnvelopedKey getInstance(Object obj) {
    if (obj instanceof SM2EnvelopedKey) {
      return (SM2EnvelopedKey) obj;
    }else if (obj !=null) {
      return new SM2EnvelopedKey(ASN1Sequence.getInstance(obj));
    }
    return null;
  }

  private SM2EnvelopedKey(ASN1Sequence seq) {
    symAlgID = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
    symEncryptedKey = SM2Cipher.getInstance(seq.getObjectAt(1));
    sm2PublicKey = SM2PublicKey.getInstance(seq.getObjectAt(2));
    sm2EncryptedPrivateKey = ASN1BitString.getInstance(seq.getObjectAt(3));
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(symAlgID);
    v.add(symEncryptedKey);
    v.add(sm2PublicKey);
    v.add(sm2EncryptedPrivateKey);
    return new DERSequence(v);
  }
}
