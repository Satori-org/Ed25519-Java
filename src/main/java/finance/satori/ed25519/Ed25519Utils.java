package finance.satori.ed25519;

import net.i2p.crypto.eddsa.*;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.*;

import java.security.*;

public class Ed25519Utils {
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

    public static PublicKey getPublic(String publicKey) {
        EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        return new EdDSAPublicKey(new EdDSAPublicKeySpec(Utils.hexToBytes(publicKey), spec));
    }

    public static Boolean ed25519VerifySign(PublicKey publicKey, String data, String signData) throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        sgr.initVerify(publicKey);
        sgr.update(data.getBytes());
        return sgr.verify(Utils.hexToBytes(signData));
    }

    public static void main(String[] args) throws Exception {
        PublicKey publicKey = getPublic("6a050aa140c99801cf2613f4a5b5de033d2ff31363d2c4ab967ffacd4d1bce34");
        Boolean aBoolean = ed25519VerifySign(publicKey, "123123", "240ab1f6d13b0092f659d2dadd667efcb8d4ce27475f29632061611a856f7e1202a7e75ab656f34838c405b7444db511a533530260bdb230bb6e4cab3f7de18c");
        System.out.println(aBoolean);
//        KeyPair keyPair = ed25519GenerateKeyPair();
//        System.out.println("privateKey:" + Utils.bytesToHex(keyPair.getPrivate().getEncoded()));
//        System.out.println("publicKey:" + Utils.bytesToHex(keyPair.getPublic().getEncoded()));
//        String message = "Hello edd25516";
//        System.out.println("message:" + message);
//        try {
//            String signStr = ed25519Sign(keyPair.getPrivate(), message.getBytes());
//            System.out.println("The sign result is : " + signStr);
//            Boolean isSuccess = ed25519VerifySign(keyPair.getPublic(), message, signStr);
//            System.out.println("The verify result is: " + isSuccess);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }
}
