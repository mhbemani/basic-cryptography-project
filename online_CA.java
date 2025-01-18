package CA;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
 

// certification verification    ...done
public class online_CA {
    public boolean certification_verification(String public_key, String r, String s){
        try{
                    String signature ="(";
                    signature += r+",\n";
                    signature += s+")";
                //   now we have r, s and the public key
                StringBuilder pemContent = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(new FileReader("CA/CA_public_key_cert_001.pem"))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.contains("-----BEGIN") || line.contains("-----END")) {
                            continue;
                        } else {
                            pemContent.append(line.trim());
                        }
                    }
                    PublicKey publicKey = decodeDSAPublicKey(pemContent.toString());
                    DSAPublicKey dsaPublicKey = (DSAPublicKey) publicKey;
                    DSAParams params = dsaPublicKey.getParams();

                    //  passing to the DSA verification function    //
                    return DSA.verification(public_key, signature, dsaPublicKey.getY(), params.getP(), params.getQ(), params.getG());
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
        }catch(Exception e){
            System.out.println(e.toString());
            return false;
        }
    }

    public static PublicKey decodeDSAPublicKey(String pem) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(pem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        return keyFactory.generatePublic(keySpec);
    }

    public void Client(String addr, int port) {
        try (Socket socket = new Socket(addr, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
    
            System.out.println("Connected to the server!");
    
            String line1;
            StringBuilder publicKey = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null && !line.equals("EOF")) {
                publicKey.append(line).append("\n");
            }
            line1 = publicKey.toString();
    
            String regex = "public_key: ([A-Za-z0-9+/=\\S\\n]+)r: (\\d+),s: (\\d+)";
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(line1.trim());
            if (matcher.find()) {
                String publicKeyStr = matcher.group(1);
                String r = matcher.group(2).trim();
                String s = matcher.group(3).trim();
                if (certification_verification(publicKeyStr, r, s)) {
                    System.out.println("valid...");
                    out.println("VALID");
                    out.flush();
                } else {
                    System.out.println("invalid...");
                    out.println("INVALID");
                    out.flush();
                }
                Thread.sleep(200); // Give the server time to process
            }
        } catch (Exception e) {
            System.err.println("Client error: " + e.getMessage());
            e.printStackTrace();
        }
        
    }

    public static void main(String[] args) {
        online_CA oc = new online_CA();
        oc.Client("127.0.0.1", 5000);
        
    }
}
