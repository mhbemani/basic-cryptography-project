package coco_128;
public class decryption_methodes {

    private static String xor_hex_128bit_2(String str1, String str2){
        String str1_1 = str1.subSequence(0, str1.length()/4).toString();
        String str1_2 = str1.subSequence(str1.length()/4, str1.length()/2).toString();
        String str1_3 = str1.subSequence(str1.length()/2, str1.length()*3/4).toString();
        String str1_4 = str1.subSequence(str1.length()*3/4, str1.length()).toString();

        String str2_1 = str2.subSequence(0, str2.length()/4).toString();
        String str2_2 = str2.subSequence(str1.length()/4, str2.length()/2).toString();
        String str2_3 = str2.subSequence(str2.length()/2, str2.length()*3/4).toString();
        String str2_4 = str2.subSequence(str1.length()*3/4, str2.length()).toString();

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

    public static String EBC(String cipherText, String key){
        String plainText = "";
        int j=0;
        for(int i=0; i<cipherText.length()/32; i++){
            plainText += encrypt_decrypt.decryption_func(cipherText.subSequence(j, j+32).toString(), key);
            j += 32;
        }
        plainText = encode_decode.decoding_func(plainText);
        return plainText;
    }
    
    public static String OFB(String cipherText, String key){
        String nonce = cipherText.subSequence(0, 32).toString();
        String plainText = "";
        int j=32;
        for(int i=0; i<cipherText.length()/32-1; i++){
            nonce = encrypt_decrypt.encryption_func(nonce, key);
            plainText += xor_hex_128bit_2(nonce, cipherText.subSequence(j, j+32).toString());
            j+= 32;
        }
        plainText = encode_decode.decoding_func(plainText);
        return plainText;
    }
    
    public static String CTR(String cipherText, String key){
        String nonce = cipherText.subSequence(0, 16).toString();
        String plainText = "";
        int counter =0;
        int j=16;
        for(int i=0; i<(cipherText.length()+16)/32-1; i++){
            String temp = Integer.toHexString(counter);
            String count = "";
            for(int k=0;k<16-temp.length();k++){
                count += "0";
            }
            count += temp;
            String nonce_round = encrypt_decrypt.encryption_func(nonce+count, key);
            plainText += xor_hex_128bit_2(nonce_round, cipherText.subSequence(j, j+32).toString());
            j+= 32;
            counter++;
        }
        plainText = encode_decode.decoding_func(plainText);
        return plainText;
    }
    
    public static String CBC(String cipherText, String key){
        String nonce = cipherText.subSequence(0, 32).toString();
        String plainText = "";
        int j=32;
        for(int i=0; i<cipherText.length()/32-1; i++){
            String temp = encrypt_decrypt.decryption_func(cipherText.subSequence(j, j+32).toString(), key);
            plainText += xor_hex_128bit_2(nonce, temp);
            nonce = cipherText.subSequence(j, j+32).toString();
            j+= 32;
        }
        plainText = encode_decode.decoding_func(plainText);
        return plainText;
    }
}
