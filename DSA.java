package CA;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DSA {
    public static String signature(String message, BigInteger private_key, BigInteger p, BigInteger q, BigInteger a) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));
            byte[] truncatedHashBytes = new byte[20];
            System.arraycopy(hashBytes, 0, truncatedHashBytes, 0, 20);
            BigInteger hash = new BigInteger(1, truncatedHashBytes);
    
            BigInteger k;
            do {
                k = new BigInteger(q.bitLength(), new Random());
            } while (k.compareTo(BigInteger.ONE) < 0 || k.compareTo(q) >= 0);
    
            BigInteger r = (a.modPow(k, p)).mod(q);
            BigInteger s = (hash.add(private_key.multiply(r)).multiply(k.modInverse(q))).mod(q);
            // System.out.println("r inside DSA.signature: "+r.toString()); ///////////////////////////////////////
            // System.out.println("s inside DSA.signature: "+s.toString()); ///////////////////////////////////////
            return "(" + r.toString() + ",\n" + s.toString() + ")";
        } catch (Exception e) {
            throw new RuntimeException("Error: something went wrong", e);
        }
    }
    
    public static boolean verification(String message, String signature, BigInteger public_key, BigInteger p, BigInteger q, BigInteger a) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));
            byte[] truncatedHashBytes = new byte[20];
            System.arraycopy(hashBytes, 0, truncatedHashBytes, 0, 20);
            BigInteger hash = new BigInteger(1, truncatedHashBytes);
    
            Pattern pattern = Pattern.compile("\\((\\d+),\\s*(\\d+)\\)");
            Matcher matcher = pattern.matcher(signature);
            BigInteger r, s;
            if (matcher.find()) {
                r = new BigInteger(matcher.group(1));
                s = new BigInteger(matcher.group(2));
                // System.out.println(r);
                // System.out.println(s);
            } else {
                System.out.println("signature is not valid");
                return false;
            }
    
            if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(q) >= 0 ||
                s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(q) >= 0) {
                return false;
            }
    
            BigInteger w = s.modInverse(q);
            BigInteger u1 = (hash.multiply(w)).mod(q);
            BigInteger u2 = (r.multiply(w)).mod(q);
            BigInteger v = ((a.modPow(u1, p)).multiply(public_key.modPow(u2, p))).mod(p).mod(q);
    
            return v.equals(r.mod(q));
        } catch (Exception e) {
            throw new RuntimeException("Error: something went wrong", e);
        }
    }
    
}
