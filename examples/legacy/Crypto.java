// Example Java code using deprecated ciphers (for demo purposes).
import javax.crypto.Cipher;
import java.security.MessageDigest;

public class Crypto {
    public void run() throws Exception {
        Cipher tripleDes = Cipher.getInstance("DESede/CBC/PKCS5Padding"); // MEDIUM: 3DES
        Cipher rc4 = Cipher.getInstance("RC4");                           // MEDIUM: RC4
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");          // HIGH: SHA-1
    }
}
