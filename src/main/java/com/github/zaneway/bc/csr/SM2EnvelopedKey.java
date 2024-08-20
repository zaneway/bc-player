package com.github.zaneway.bc.csr;

import com.github.zaneway.bc.sm2.SM2Cipher;
import java.io.IOException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class SM2EnvelopedKey extends ASN1Object {

  private ASN1Sequence seq;
  //对称密码算法标识
  private AlgorithmIdentifier symAlgId;
  //对称密钥密文
  private SM2Cipher symEncryptedKey;
  //公钥
  private DERBitString sm2PublicKey;
  //私钥密文
  private DERBitString sm2EncPrivateKey;


  public SM2EnvelopedKey(byte[] encoded) throws IOException {
    DLSequence dl = (DLSequence) ASN1Primitive.fromByteArray(encoded);
    this.symAlgId = AlgorithmIdentifier.getInstance(dl.getObjectAt(0));
    this.symEncryptedKey = new SM2Cipher(dl.getObjectAt(1).toASN1Primitive().getEncoded());
    this.sm2PublicKey = (DERBitString) dl.getObjectAt(2);
    this.sm2EncPrivateKey = (DERBitString) dl.getObjectAt(3);
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(symAlgId);
    v.add(symEncryptedKey);
    v.add(sm2PublicKey);
    v.add(sm2EncPrivateKey);
    seq = new DERSequence(v);
  }

  public SM2EnvelopedKey(AlgorithmIdentifier symAlgId,
      SM2Cipher symEncryptedKey, DERBitString sm2PublicKey,
      DERBitString sm2EncPrivateKey) {
    this.symAlgId = symAlgId;
    this.symEncryptedKey = symEncryptedKey;
    this.sm2PublicKey = sm2PublicKey;
    this.sm2EncPrivateKey = sm2EncPrivateKey;
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(symAlgId);
    v.add(symEncryptedKey);
    v.add(sm2PublicKey);
    v.add(sm2EncPrivateKey);
    seq = new DERSequence(v);
  }


  public static SM2EnvelopedKey getInstance(Object obj) throws IllegalArgumentException {
    try {
      if (obj instanceof SM2EnvelopedKey) {
        return (SM2EnvelopedKey) obj;
      } else if (obj instanceof byte[]) {
        return new SM2EnvelopedKey((byte[]) obj);
      } else if (obj instanceof ASN1Sequence) {
        ASN1Sequence sequence = (ASN1Sequence) obj;
        new SM2EnvelopedKey(sequence.getEncoded(ASN1Encoding.DER));
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

  public AlgorithmIdentifier getSymAlgId() {
    return symAlgId;
  }

  public SM2Cipher getSymEncryptedKey() {
    return symEncryptedKey;
  }

  public DERBitString getSm2PublicKey() {
    return sm2PublicKey;
  }

  public DERBitString getSm2EncPrivateKey() {
    return sm2EncPrivateKey;
  }


}
