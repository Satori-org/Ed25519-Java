package finance.satori.sr25519;


import finance.satori.schnorrkel.Schnorrkel;
import finance.satori.sr25519.core.*;
import finance.satori.sr25519.core.util.ByteData;
import net.i2p.crypto.eddsa.Utils;

import java.util.Arrays;

public class SR25519Utils {
    public static void main(String[] args) throws Exception {


        KeyPair pair = KeyPair.fromSecretSeed(Utils.hexToBytes("5a79c0f70226c3778c54d48be3df254144856dcee62d8c8c9fcb3ebc65d73194"), ExpansionMode.Sr25519);
        byte[] message = "123123".getBytes();
        System.out.println(Utils.bytesToHex(pair.getPublicKey().toPublicKey()));
        SigningContext ctx = SigningContext.createSigningContext("substrate".getBytes());
        SigningTranscript t = ctx.bytes(message);
        Signature signature = pair.sign(t);
        byte[] sign = signature.to_bytes();
        System.out.println("pair sign:" + Utils.bytesToHex(sign));
        Schnorrkel.KeyPair pair1 = Schnorrkel.getInstance().generateKeyPairFromSeed(Utils.hexToBytes("5a79c0f70226c3778c54d48be3df254144856dcee62d8c8c9fcb3ebc65d73194"));
        byte[] sign1 = Schnorrkel.getInstance().sign("123123".getBytes(), pair1);
        System.out.println("pair1 sign:" + Utils.bytesToHex(sign1));


        System.out.println(Utils.bytesToHex(pair.getPublicKey().toPublicKey()));
        System.out.println(Arrays.toString(pair1.getPublicKey()));

        boolean verify = Schnorrkel.getInstance().verify(sign,
                message,
                new Schnorrkel.PublicKey(pair1.getPublicKey()));
        System.out.println("验证结果:" + verify);

        SigningContext signingContext = SigningContext.createSigningContext("substrate".getBytes());
        SigningTranscript t2 = signingContext.bytes("123123".getBytes());
        boolean verify2 = pair.verify(t2, sign1);
        System.out.println("验证结果2:" + verify2);
        byte[] bytes = ByteData.from("06759706a04f27d8a1b4a10a9e2272db9c6022dd63cf55506ba77392643aef0695f440df71640077137b6a80256fed46ab004603ec0ffffdb28a3b9df165a08c").getBytes();
        System.out.println(Arrays.toString(bytes));



        boolean verify3 = Schnorrkel.getInstance().verify(bytes,
                message,
                new Schnorrkel.PublicKey(pair1.getPublicKey()));
        System.out.println("验证结果3:" + verify3);

        boolean verify4 = pair.verify(t2, bytes);
        System.out.println("验证结果4:" + verify4);
    }

    public static byte[] hexToByte(String str) {
        byte[] bytes = new byte[str.length() / 2];
        for(int i = 0; i < str.length() / 2; i++) {
            String subStr = str.substring(i * 2, i * 2 + 2);
            bytes[i] = (byte) Integer.parseInt(subStr, 16);
        }
        System.out.println(bytes.length);
        return bytes;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        try {
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                        + Character.digit(s.charAt(i+1), 16));
            }
        } catch (Exception e) {
            // Log.d("", "Argument(s) for hexStringToByteArray(String s)"+ "was not a hex string");
        }
        return data;
    }
}
