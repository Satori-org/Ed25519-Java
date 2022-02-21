package finance.satori.sr25519.core.util;

public class ScalarUtils {
    public static byte[] divide_scalar_bytes_by_cofactor(byte[] scalar) {
        int low = 0;
        for (int i = scalar.length - 1; i >= 0; i--) {
            int b = scalar[i] & 0xFF;
            int r = b & 0b00000111;
            b >>= 3;
            b += low;
            low = r << 5;
            scalar[i] = (byte) b;
        }
        return scalar;
    }
}
