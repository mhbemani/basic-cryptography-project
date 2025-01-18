package Client;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.xml.crypto.dsig.spec.RSAPSSParameterSpec;

import org.json.JSONObject;
import org.json.JSONException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import org.json.JSONTokener;
import org.json.simple.*;

// import junit.framework.TestCase;

import asymmetric.prime;

// generate client's RSA keys (public and private)    ...done
// store the private key in client_private_key.pem    ...done
// store the public key in /CSR/csr.json              ...done
public class offline_client { 
    public void keyGenAndStore(){
        prime p = new prime();
        p.RSA_key_generator();
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(p.modulo, p.RSA_private_key);
        
        try{
            ////    FOR  PRIVATE  KEY    ////
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            String privateKeyPEM = convertToPEM(privateKey);
            try (FileOutputStream fos = new FileOutputStream("Client/client_private_key.pem")) {
                fos.write(privateKeyPEM.getBytes());
            }
            ////    FOR  PUBLIC  KEY    ////
            String publicKey = PUBconvertToPEM(p.modulo, p.RSA_public_key);
            String content = new String(Files.readAllBytes(Paths.get("./CSR/csr.json")));
            JSONObject jsonObject = new JSONObject(content);
            if (jsonObject.has("public_key")) {
                jsonObject.put("public_key", publicKey);
                
            } else {
                System.out.println("Key not found in the JSON.");
            }
            Files.write(Paths.get("./CSR/csr.json"), jsonObject.toString(4).getBytes());  // Pretty print with 4 spaces indentation
        }catch(Exception e){
            System.out.println(e.toString());
        }
    }

    public static String PUBconvertToPEM(BigInteger modulus, BigInteger exponent) throws Exception {
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        byte[] derEncoded = publicKey.getEncoded();
        String base64Encoded = Base64.getEncoder().encodeToString(derEncoded);
        StringWriter pemWriter = new StringWriter();
        pemWriter.write("-----BEGIN PUBLIC KEY-----\n");
        int lineLength = 64;
        for (int i = 0; i < base64Encoded.length(); i += lineLength) {
            int endIndex = Math.min(i + lineLength, base64Encoded.length());
            pemWriter.write(base64Encoded, i, endIndex - i);
            pemWriter.write("\n");
        }
        return pemWriter.toString();
    }

    static String convertToPEM(PrivateKey privateKey){
        String base64Key = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN PRIVATE KEY-----\n");
        for (int i = 0; i < base64Key.length(); i += 64) {
            pem.append(base64Key, i, Math.min(i + 64, base64Key.length())).append("\n");
        }
        pem.append("-----END PRIVATE KEY-----");
        return pem.toString();
    }
    public static void main(String[] args) {
        offline_client oc = new offline_client();
        oc.keyGenAndStore();
    }

}
