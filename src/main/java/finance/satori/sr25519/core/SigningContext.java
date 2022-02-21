package finance.satori.sr25519.core;

import finance.satori.sr25519.core.merlin.Transcript;

public class SigningContext {
    private Transcript transcript;

    public SigningContext(Transcript transcript) {
        this.transcript = transcript;
    }

    public static SigningContext createSigningContext(byte[] context) throws Exception {
        Transcript t = Transcript.createTranscript("SigningContext".getBytes());
        t.append_message("".getBytes(), context);
        return new SigningContext(t);
    }

    public SigningTranscript bytes(byte[] bytes) throws Exception {
        SigningTranscript t = new SigningTranscript(this.transcript.getStrobe());
        t.append_message("sign-bytes".getBytes(), bytes);
        return t;
    }
}
