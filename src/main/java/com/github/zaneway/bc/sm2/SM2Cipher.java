package com.github.zaneway.bc.sm2;

import java.io.IOException;
import lombok.Getter;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;

@Getter
public class SM2Cipher extends ASN1Object {

  private final ASN1Sequence seq;

  private final ASN1Integer x;

  private final ASN1Integer y;

  private final DEROctetString hash;

  private final DEROctetString cipherText;

  public SM2Cipher(byte[] encoded) throws IOException {
    DLSequence sm2Cipher = (DLSequence) ASN1Primitive.fromByteArray(encoded);
    this.x = (ASN1Integer) sm2Cipher.getObjectAt(0);
    this.y = (ASN1Integer) sm2Cipher.getObjectAt(1);
    this.hash = (DEROctetString) sm2Cipher.getObjectAt(2);
    this.cipherText = (DEROctetString) sm2Cipher.getObjectAt(3);
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(x);
    v.add(y);
    v.add(hash);
    v.add(cipherText);
    seq = new DERSequence(v);
  }

  public SM2Cipher(ASN1Integer x, ASN1Integer y, DEROctetString hash, DEROctetString cipherText) {
    if (hash.getOctets().length != 32) {
      throw new IllegalArgumentException("hash length must be 32");
    }
    this.x = x;
    this.y = y;
    this.hash = hash;
    this.cipherText = cipherText;
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(x);
    v.add(y);
    v.add(hash);
    v.add(cipherText);
    seq = new DERSequence(v);
  }


  public static SM2Cipher getInstance(Object obj) {
    try {
      if (obj instanceof SM2Cipher) {
        return (SM2Cipher) obj;
      } else if (obj instanceof ASN1Sequence) {
        return new SM2Cipher(((ASN1Sequence) obj).getEncoded());
      } else if (obj instanceof byte[]) {
        return new SM2Cipher((byte[]) obj);
      }
    } catch (Exception e) {
      throw new IllegalArgumentException(
          "illegal object in getInstance: " + obj.getClass().getName(), e);
    }
    return null;
  }


  public byte[] getEncoded() throws IOException {
    return this.seq.getEncoded();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.seq;
  }

  public ASN1Integer getX() {
    return x;
  }

  public ASN1Integer getY() {
    return y;
  }

  public DEROctetString getHash() {
    return hash;
  }

  public DEROctetString getCipherText() {
    return cipherText;
  }


}