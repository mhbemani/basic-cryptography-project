package CA;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONObject;
import org.json.JSONException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import asymmetric.prime;

// generate public and private keys and store them in CA/.pem files                         ...done
// accses /CSR/csr.json , sign it and store the signiture in /CERT/client_cert_001.json     ...done
public class offline_CA {
    
    public void certification_signature(){
        try {       ////   how to extract from JSON    ////
            String content = new String(Files.readAllBytes(Paths.get("./CSR/csr.json")));
            JSONObject jsonObject = new JSONObject(content);
            String value = "";
            if (jsonObject.has("public_key")) {
                value = jsonObject.getString("public_key");
                value = value.substring(27);
                value = value.trim();
                ////    USER'S  PUBLIC  KEY  EXTRACTED    ////
                // try{
                //     value = decodeRSAPublicKey(value).toString();
                //     System.out.println(value);
                //     String regex = "modulus:\\s*(\\d+)\\s*public exponent:\\s*(\\d+)";
                //     Pattern pattern = Pattern.compile(regex);
                //     Matcher matcher = pattern.matcher(value);
                //     if (matcher.find()) {
                //         String modulusStr = matcher.group(1);
                //         String exponentStr = matcher.group(2);
                //         BigInteger modulus = new BigInteger(modulusStr);
                //         BigInteger exponent = new BigInteger(exponentStr);
                //
                //     } else {
                //         System.out.println("Modulus and Exponent not found.");
                //     }
                // }catch(Exception e){
                //     System.out.println(e.toString());
                // }
            } else {
                System.out.println("user's publicKey not found.");
            }
            StringBuilder pemContent = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new FileReader("CA/CA_private_key_cert_001.pem"))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("-----BEGIN") || line.contains("-----END")) {
                        continue;
                    } else {
                        pemContent.append(line.trim());
                    }
                }
                try{
                PrivateKey pk = decodeDSAPrivateKey(pemContent.toString());
                DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) pk;
                DSAParams params = dsaPrivateKey.getParams();
                String signatureSTR = DSA.signature(value, dsaPrivateKey.getX(), params.getP(), params.getQ(), params.getG());
                Pattern pattern = Pattern.compile("\\((\\d+),\\s*(\\d+)\\)");
                Matcher matcher = pattern.matcher(signatureSTR);
                BigInteger r = BigInteger.ZERO;
                BigInteger s = BigInteger.ZERO;



                if (matcher.find()) {
                    r = new BigInteger(matcher.group(1));
                    s = new BigInteger(matcher.group(2));
                } else {
                    System.out.println("signature is not valid");
                }
                content = new String(Files.readAllBytes(Paths.get("./CERT/cilent_cert_001.json")));
                jsonObject = new JSONObject(content);
                if (jsonObject.has("public_key")) {
                    jsonObject.put("public_key", value);
                    
                } else {
                    System.out.println("Key not found");
                }
                if (jsonObject.has("signature")) {
                    JSONObject signature = jsonObject.getJSONObject("signature");
                    signature.put("r", r.toString());
                    signature.put("s", s.toString());
                    Files.write(Paths.get("./CERT/cilent_cert_001.json"), jsonObject.toString(4).getBytes());
                } else {
                    System.out.println("Key 'signature' not found");
                }
            }catch(Exception e){
                System.out.println(e.toString());
            }
        }
        } catch (IOException | JSONException e) {
            e.printStackTrace();
        }
    }

    public static PrivateKey extractPrivateKeyFromPEM(String pemFilePath) {
        try {
            StringBuilder pemContent = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new FileReader(pemFilePath))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("-----BEGIN PRIVATE KEY-----") || line.contains("-----END PRIVATE KEY-----")) {
                        continue;
                    }
                    pemContent.append(line.trim());
                }
            }
            byte[] derEncoded = Base64.getDecoder().decode(pemContent.toString());
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(derEncoded);
            KeyFactory keyFactory = KeyFactory.getInstance("DSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static PublicKey decodeRSAPublicKey(String pem) throws Exception {
        // Step 1: Remove PEM headers and footers
        String base64Key = pem.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                              .replaceAll("-----END PUBLIC KEY-----", "")
                              .replaceAll("\\s", ""); // Remove all whitespace
        
        // Step 2: Decode Base64 content
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);

        // Step 3: Create a PublicKey from the decoded bytes
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        return publicKey;
    }

    public static PrivateKey decodeDSAPrivateKey(String pem) throws Exception {
        String base64Key = pem.replaceAll("-----BEGIN DSA PRIVATE KEY-----", "")
                              .replaceAll("-----END DSA PRIVATE KEY-----", "")
                              .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    public void keyGen(){ // generate and store the keys
        prime p = new prime();
        p.DSA_key_generator();
        try{
            String privateKeyPEMFormat = PRIconvertToPEM(p.DSA_d, p.DSA_p, p.DSA_q, p.DSA_a);
            try (FileOutputStream fos = new FileOutputStream("CA/CA_private_key_cert_001.pem")) {
                fos.write(privateKeyPEMFormat.getBytes());
            }
            String publicKeyPEMFormat = PUBconvertToPEM(p.DSA_b, p.DSA_p, p.DSA_q, p.DSA_a);
            try (FileOutputStream fos = new FileOutputStream("CA/CA_public_key_cert_001.pem")) {
                fos.write(publicKeyPEMFormat.getBytes());
            }
        }catch(Exception e){
            System.out.println(e.toString());
        }
        
    }
    
    public String PRIconvertToPEM(BigInteger privateKey, BigInteger p, BigInteger q, BigInteger a) throws Exception {
        DSAPrivateKeySpec privateKeySpec = new DSAPrivateKeySpec(privateKey, p, q, a);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        PrivateKey key = keyFactory.generatePrivate(privateKeySpec);
        byte[] derEncoded = key.getEncoded();
        String base64Encoded = Base64.getEncoder().encodeToString(derEncoded);
        StringWriter pemWriter = new StringWriter();
        pemWriter.write("-----BEGIN PRIVATE KEY-----\n");
        int lineLength = 64;
        for (int i = 0; i < base64Encoded.length(); i += lineLength) {
            int endIndex = Math.min(i + lineLength, base64Encoded.length());
            pemWriter.write(base64Encoded, i, endIndex - i);
            pemWriter.write("\n");
        }
        pemWriter.write("-----END PRIVATE KEY-----\n");
        return pemWriter.toString();
    }

    public static String PUBconvertToPEM(BigInteger publicKey, BigInteger p, BigInteger q, BigInteger a) throws Exception {
        DSAPublicKeySpec publicKeySpec = new DSAPublicKeySpec(publicKey, p, q, a);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        PublicKey key = keyFactory.generatePublic(publicKeySpec);
        byte[] derEncoded = key.getEncoded();
        String base64Encoded = Base64.getEncoder().encodeToString(derEncoded);
        StringWriter pemWriter = new StringWriter();
        pemWriter.write("-----BEGIN PUBLIC KEY-----\n");
        int lineLength = 64;
        for (int i = 0; i < base64Encoded.length(); i += lineLength) {
            int endIndex = Math.min(i + lineLength, base64Encoded.length());
            pemWriter.write(base64Encoded, i, endIndex - i);
            pemWriter.write("\n");
        }
        pemWriter.write("-----END PUBLIC KEY-----\n");
        return pemWriter.toString();
    }

    public static void main(String[] args) {
        offline_CA of = new offline_CA();
        of.certification_signature();
    }
}
