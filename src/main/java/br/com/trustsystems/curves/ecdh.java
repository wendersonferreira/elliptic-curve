package br.com.trustsystems.curves;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import java.util.*;
import java.nio.ByteBuffer;
import java.io.Console;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;

public class ecdh {
    public static void main(String[] args) throws Exception {
        Console console = System.console();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        byte[] ourPk = kp.getPublic().getEncoded();

        console.printf("Public Key: %s%n", printHexBinary(ourPk));

        byte[] otherPk = parseHexBinary(console.readLine("Other PK: "));

        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(otherPk);
        PublicKey otherPublicKey = kf.generatePublic(pkSpec);

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(kp.getPrivate());
        ka.doPhase(otherPublicKey, true);

        byte[] sharedSecret = ka.generateSecret();
        console.printf("Shared secret: %s%n", printHexBinary(sharedSecret));

        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(sharedSecret);

        List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(otherPk));
        Collections.sort(keys);
        hash.update(keys.get(0));
        hash.update(keys.get(1));

        byte[] derivedKey = hash.digest();
        console.printf("Final key: %s%n", printHexBinary(derivedKey));
    }
}
