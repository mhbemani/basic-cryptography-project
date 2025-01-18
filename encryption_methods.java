package coco_128;
import java.util.Random;

public class encryption_methods {
    
    private static String xor_hex_128bit_2(String str1, String str2){
        String str1_1 = str1.subSequence(0, str1.length()/4).toString();
        String str1_2 = str1.subSequence(str1.length()/4, str1.length()/2).toString();
        String str1_3 = str1.subSequence(str1.length()/2, str1.length()*3/4).toString();
        String str1_4 = str1.subSequence(str1.length()*3/4, str1.length()).toString();

        String str2_1 = str2.subSequence(0, str2.length()/4).toString();
        String str2_2 = str2.subSequence(str2.length()/4, str2.length()/2).toString();
        String str2_3 = str2.subSequence(str2.length()/2, str2.length()*3/4).toString();
        String str2_4 = str2.subSequence(str2.length()*3/4, str2.length()).toString();

        String temp1 = Long.toHexString(Long.parseLong(str1_1, 16) ^ Long.parseLong(str2_1, 16));
        String temp2 = Long.toHexString(Long.parseLong(str1_2, 16) ^ Long.parseLong(str2_2, 16));
        String temp3 = Long.toHexString(Long.parseLong(str1_3, 16) ^ Long.parseLong(str2_3, 16));
        String temp4 = Long.toHexString(Long.parseLong(str1_4, 16) ^ Long.parseLong(str2_4, 16));
        String s = "";
        for(int i=0;i<8-temp1.length();i++){
            s += "0";
        }
        s += temp1;
        for(int i=0;i<8-temp2.length();i++){
            s += "0";
        }
        s += temp2;
        for(int i=0;i<8-temp3.length();i++){
            s += "0";
        }
        s += temp3;
        for(int i=0;i<8-temp4.length();i++){
            s += "0";
        }
        s += temp4;
        return s;
    }

    public static String EBC(String plainText, String key){
        String encoded_pt = encode_decode.encoding_func(plainText);
        String cipherText = "";
        int j=0;
        for(int i=0; i<encoded_pt.length()/32; i++){
            cipherText += encrypt_decrypt.encryption_func(encoded_pt.subSequence(j, j+32).toString(), key);
            j += 32;
        }
        return cipherText;
    }
    
    public static String OFB(String plainText, String key){
        String encoded_pt = encode_decode.encoding_func(plainText);
        Random random = new Random();
        String nonce = "";
        for(int i=0; i<16;i++){
            String temp = Integer.toHexString(random.nextInt(255));
            if(temp.length() == 1){
                nonce += "0"+temp;
            }else{
                nonce += temp;
            }
        }
        String cipherText = nonce;
        int j=0;
        for(int i=0; i<encoded_pt.length()/32; i++){
            nonce = encrypt_decrypt.encryption_func(nonce, key);
            cipherText += xor_hex_128bit_2(nonce, encoded_pt.subSequence(j, j+32).toString());
            j+= 32;
        }
        return cipherText;
    }
    
    public static String CTR(String plainText, String key){
        String encoded_pt = encode_decode.encoding_func(plainText);
        Random random = new Random();
        String nonce = "";
        for(int i=0; i<8;i++){
            String temp = Integer.toHexString(random.nextInt(255));
            if(temp.length() == 1){
                nonce += "0"+temp;
            }else{
                nonce += temp;
            }
        }
        String cipherText = nonce;
        int counter = 0;
        int j=0;
        for(int i=0; i<encoded_pt.length()/32; i++){
            String temp = Integer.toHexString(counter);
            String count = "";
            for(int k=0;k<16-temp.length();k++){
                count += "0";
            }
            count += temp;
            String nonce_round = encrypt_decrypt.encryption_func(nonce+count, key);
            cipherText += xor_hex_128bit_2(nonce_round, encoded_pt.subSequence(j, j+32).toString());
            j+= 32;
            counter++;
        }
        return cipherText;
    }
    
    public static String CBC(String plainText, String key){
        String encoded_pt = encode_decode.encoding_func(plainText);
        Random random = new Random();
        String nonce = "";
        for(int i=0; i<16;i++){
            String temp = Integer.toHexString(random.nextInt(255));
            if(temp.length() == 1){
                nonce += "0"+temp;
            }else{
                nonce += temp;
            }
        }
        String cipherText = nonce;
        int j=0;
        for(int i=0; i<encoded_pt.length()/32; i++){
            nonce = encrypt_decrypt.encryption_func(xor_hex_128bit_2(nonce, encoded_pt.subSequence(j, j+32).toString()), key);
            cipherText += nonce;
            j+= 32;
        }
        return cipherText;
    }
}
