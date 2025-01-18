package Server;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import coco_128.decryption_methodes;

import CA.offline_CA;
import asymmetric.RSA;

// after reciving the message and signature from client, sends them to CA_online for
// verification 
public class server {
    public static boolean flag = false;
    public static String certification;
    public static String certification_validity = "not determined";
     
    public void Server_final(int port) {
        try {
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server is running...");

            Socket socket1 = serverSocket.accept(); // Wait for a client to connect
            System.out.println("Connection recived from (\"127.0.0.1 , 5000\")");
            
            PrintWriter out = new PrintWriter(socket1.getOutputStream(), true);
            String message = "";
            // System.out.println(flag);
            if(!flag){
                message = "RSA_PUBLIC_KEY_CERTIFICATION_NEEDED.";
                out.println(message);
            }
            while (true) {
                        try (BufferedReader reader = new BufferedReader(new InputStreamReader(socket1.getInputStream()))) {
                            
                            StringBuilder publicKey = new StringBuilder();
                            String line;
                            
                            // Read until the end marker
                            while ((line = reader.readLine()) != null && !line.equals("EOF")) {
                                publicKey.append(line).append("\n");
                            }
                            certification = publicKey.toString();
                            break;
                        }
            }
        socket1.close();
            Socket socket2 = serverSocket.accept(); // Wait for a client to connect
            BufferedReader in = new BufferedReader(new InputStreamReader(socket2.getInputStream()));
            message = certification;
            PrintWriter writer = new PrintWriter(socket2.getOutputStream(), true);

                String[] lines = message.split("\n");
                for (String line : lines) {
                    writer.println(line);
                }
                writer.println("EOF"); // End marker
                writer.flush(); // Ensure all data is sent

            while (true) {
                try{
                    String response = in.readLine(); // Wait for response
                    if (response != null) {
                        System.out.println("Client: " + response);
                        if(response.equals("VALID")) System.out.println("Certification verified, generation symmetric key...");
                        if(response.equals("INVALID")) System.out.println("Certification denied.");
                        if (response.equals("VALID") || response.equals("INVALID")) {
                            certification_validity = response; // Update global state
                            break;
                        }
                    }
                }catch(Exception e){
                    System.out.println(e.toString());
                    break;
                }
            }
            // // socket.setSoTimeout(5000); 
            socket2.close();
            socket1 = serverSocket.accept();
            //////    IT  IS  CONNECTED  SUCCESFULLY    ////

            Pattern pattern = Pattern.compile("public_key: ([A-Za-z0-9+/=\\S\\n]+)r: (\\d+),s: (\\d+)");
            Matcher matcher = pattern.matcher(certification);
            if (matcher.find()) {
                String publicKeyStr = matcher.group(1);
                String publicKeyBase64 = publicKeyStr
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", ""); // Remove all whitespace

            byte[] decodedKey = Base64.getDecoder().decode(publicKeyBase64);

            // Convert to RSAPublicKey
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

            BigInteger modulus = rsaPublicKey.getModulus();
            BigInteger exponent = rsaPublicKey.getPublicExponent();

                RSA r = new RSA();
                SecureRandom secureRandom = new SecureRandom();
                byte[] key = new byte[16];
                secureRandom.nextBytes(key);
                StringBuilder keyHex = new StringBuilder();
                for (byte b : key) {
                    keyHex.append(String.format("%02X", b));
                }
                BigInteger coco_key = new BigInteger(keyHex.toString(), 16);
                FileOutputStream fos = new FileOutputStream("Server/coco_key.pem");
                    for (byte b : key){
                        fos.write(b);
                    }
                    System.out.println("Hex: "+coco_key); //////////////////////////////////////
                    
                BigInteger coco_key_to_send = r.encryption(coco_key, exponent, modulus); 
                ///////     COCO   SYMMETRIC   KEY   GENERATED      ////////
                writer = new PrintWriter(socket1.getOutputStream(), true);
                writer.println("cocoKeyEncrypted: "+coco_key_to_send);
                writer.flush(); // Ensure all data is sent
                System.out.println("Encrypted symmetric key sent.");
                System.out.println("Encryption mode 'CBC' sent.");
                BufferedReader inn = new BufferedReader(new InputStreamReader(socket1.getInputStream()));
                message = inn.readLine();
                System.out.println("-->  "+coco_key.toString(16)); //////////////////////////////////////
                message = decryption_methodes.CBC(message, coco_key.toString(16));
                System.out.println("Client's decrypted message: "+message);

                socket1.close();
                fos.close();
            }else{
                System.out.println("something went wrong...");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        server se = new server();
        se.Server_final(5000);
    }
}
