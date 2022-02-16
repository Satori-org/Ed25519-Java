package finance.satori.edd25519;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;

import java.security.*;

public class Edd25519Utils {
    public static KeyPair ed25519GenerateKeyPair() {
        KeyPairGenerator generator = new KeyPairGenerator();
        return generator.generateKeyPair();
    }

    public static String ed25519Sign(PrivateKey privateKey, byte[] date) throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        sgr.initSign(privateKey);
        sgr.update(date);
        return Utils.bytesToHex(sgr.sign());
    }

    public static PrivateKey getEd25519PrivateKey(String privateKey) {
        EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        return new EdDSAPrivateKey(new EdDSAPrivateKeySpec(Utils.hexToBytes(privateKey), spec));
    }

    public static Boolean ed25519VerifySign(PublicKey publicKey, String data, String signData) throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        sgr.initVerify(publicKey);
        sgr.update(data.getBytes());
        return sgr.verify(Utils.hexToBytes(signData));
    }

    public static void main(String[] args) {
        KeyPair keyPair = ed25519GenerateKeyPair();
        System.out.println("privateKey:" + Utils.bytesToHex(keyPair.getPrivate().getEncoded()));
        System.out.println("publicKey:" + Utils.bytesToHex(keyPair.getPublic().getEncoded()));
        String message = "Hello edd25516";
        System.out.println("message:" + message);
        try {
            String signStr = ed25519Sign(keyPair.getPrivate(), message.getBytes());
            System.out.println("The sign result is : " + signStr);
            Boolean isSuccess = ed25519VerifySign(keyPair.getPublic(), message, signStr);
            System.out.println("The verify result is: " + isSuccess);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
