package com.github.zaneway.bc;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.encoders.Hex;

public class Main {

  public static void main(String[] args) throws Exception {
    BouncyCastleProvider provider = new BouncyCastleProvider();
    KeyPairGenerator generator = KeyPairGenerator.getInstance("Kyber", provider);
    generator.initialize(KyberParameterSpec.kyber512);
    KeyPair keyPair = generator.generateKeyPair();


    Cipher cipher = Cipher.getInstance("Kyber", provider);
    cipher.init(Cipher.WRAP_MODE,keyPair.getPublic());
    byte[] wrap = cipher.wrap(new Key() {
      @Override
      public String getAlgorithm() {
        return "";
      }

      @Override
      public String getFormat() {
        return "";
      }

      @Override
      public byte[] getEncoded() {
        return new byte[128];
      }
    });
    System.out.println(Hex.toHexString(wrap));


  }
}