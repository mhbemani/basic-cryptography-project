package Client;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
 
import coco_128.encryption_methods;
import org.json.JSONObject;

import asymmetric.RSA;

public class online_client {

    public void Client(String addr, int port){
        try (Socket socket = new Socket(addr, port)) {
            // System.out.println("Connected to the server!");

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader console = new BufferedReader(new InputStreamReader(System.in));

            String message;
            while (true) {
                // Client receives a message
                if ((message = in.readLine()) != null) {
                    
                    if(message.equals("RSA_PUBLIC_KEY_CERTIFICATION_NEEDED.")){
                        System.out.println("Server requested certification.");
                        try{
                            String content = new String(Files.readAllBytes(Paths.get("./CERT/cilent_cert_001.json")));
                            JSONObject jsonObject = new JSONObject(content);
                            String public_key = "";
                            if (jsonObject.has("public_key")) {
                                public_key = jsonObject.getString("public_key");
                            } else {
                                System.out.
                                println("user's publicKey not found.");
                            }
                            message = "CERTIFICATION: "+"public_key: "+public_key;
                            if (jsonObject.has("signature")) {
                                jsonObject = jsonObject.getJSONObject("signature");
                                message += "r: "+jsonObject.getString("r")+",";
                                message += "s: "+jsonObject.getString("s");
                                // System.out.println(message);
                            } else {
                                System.out.println("Key 'signature' not found");
                            }
                            try (PrintWriter writer = new PrintWriter(socket.getOutputStream(), true)) {
                                String[] lines = message.split("\n");
                                for (String line : lines) {
                                    writer.println(line);
                                }
                                writer.println("EOF"); // End marker
                            }
                            break;

                        }catch(Exception e){
                            e.toString();
                        }
                    }
            /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                   if(message.substring(0,18).equals("cocoKeyEncrypted: ")){
                        
                        String cocoKeyEncrypted = message.substring(18);
                        
                        ////   RSA decryption    ////
                        try{
                            RSAPrivateKey rsaPrivateKey = RSAPRIFROMPEM("Client/client_private_key.pem");
                            BigInteger cocoBIG = new BigInteger(cocoKeyEncrypted);
                            RSA r = new RSA();
                            BigInteger cocoKeyDecrypted = r.decryption(cocoBIG, rsaPrivateKey.getPrivateExponent(), rsaPrivateKey.getModulus());
                            String text = "There is nothing more to be said or to be done tonight, so hand me over my violin and let us try to forget\n" + //
                                                                "for half an hour the miserable weather and the still more miserable ways of our fellowmen.";
                            System.out.println("symmetric_key_hex: "+cocoKeyDecrypted.toString(16));
                            System.out.println("Encryption_mode: CBC");
                            System.out.println("Message sent.");
                            String encryptedMessage = encryption_methods.CBC(text, cocoKeyDecrypted.toString(16));
                            ////    just send it   /////
                            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
                            writer.println(encryptedMessage);
                            writer.flush();
                        }catch(Exception e){
                            e.printStackTrace();
                        }
  
                    }
                    if ("exit".equalsIgnoreCase(message)) {
                        System.out.println("Server disconnected.");
                        break;
                    }
                }
            }

            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public RSAPrivateKey RSAPRIFROMPEM(String fliePath) throws Exception{
        String pemFilePath = fliePath;
        
            // Read the PEM file content
            String pemContent = new String(Files.readAllBytes(Paths.get(pemFilePath)));
    
            // Remove the PEM headers and footers
            pemContent = pemContent.replace("-----BEGIN PRIVATE KEY-----", "")
                                   .replace("-----END PRIVATE KEY-----", "")
                                   .replaceAll("\\s", "");
    
            // Decode the Base64 content
            byte[] keyBytes = Base64.getDecoder().decode(pemContent);
    
            // Create a KeyFactory for RSA
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    
            // Generate the PrivateKey object from the key bytes
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
    
            // Cast to RSAPrivateKey to extract parameters
            
                RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
                return rsaPrivateKey;     
        
    }

    public static void main(String[] args) {
        online_client oc = new online_client();
        oc.Client("127.0.0.1", 5000);
        
    }
}
