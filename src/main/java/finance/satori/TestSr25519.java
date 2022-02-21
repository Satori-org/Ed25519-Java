package finance.satori;

import finance.satori.sr25519.core.*;
import net.i2p.crypto.eddsa.Utils;

public class TestSr25519 {

    public static void main(String[] args) throws Exception {
        KeyPair pair = KeyPair.fromSecretSeed(Utils.hexToBytes("5a79c0f70226c3778c54d48be3df254144856dcee62d8c8c9fcb3ebc65d73194"), ExpansionMode.Sr25519);
        //The message like <Bytes>$msg</Bytes>
        byte[] message = "<Bytes>123123</Bytes>".getBytes();
        testSign(pair, message);
        byte[] sign = Utils.hexToBytes("ce88f2591595ff7418fd242fa064327331967ed8f031f5f73c4ecbca5501cd345c06f24524c67df11b5d98e0c97a4dea717e96fab0549c66111ddfcb9142298a");
        testVerify(sign, message, pair);
    }


    public static void testSign(KeyPair pair, byte[] message) throws Exception {
        System.out.println("publicKey" + Utils.bytesToHex(pair.getPublicKey().toPublicKey()));
        SigningContext ctx = SigningContext.createSigningContext("substrate".getBytes());
        SigningTranscript t = ctx.bytes(message);
        Signature signature = pair.sign(t);
        byte[] sign = signature.to_bytes();

        System.out.println("sign is:" + Utils.bytesToHex(sign));

        testVerify(sign, message, pair);
        System.out.println("-----------------------");
    }

    /**
     * 验证签名
     *
     * @throws Exception
     */
    public static void testVerify(byte[] sign, byte[] message, KeyPair pair) throws Exception {
        System.out.println("publicKey" + Utils.bytesToHex(pair.getPublicKey().toPublicKey()));
        SigningContext signingContext = SigningContext.createSigningContext("substrate".getBytes());
        SigningTranscript t2 = signingContext.bytes(message);
        boolean verify = pair.verify(t2, sign);
        System.out.println("result:" + verify);
    }
}
