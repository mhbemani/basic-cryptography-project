package coco_128;
public class encrypt_decrypt {

    private static String xor_hex_64bit_2(String str1, String str2){
        String str1l = str1.subSequence(0, str1.length()/2).toString();
        String str1r = str1.subSequence(str1.length()/2, str1.length()).toString();
        String str2r = str2.subSequence(0, str2.length()/2).toString();
        String str2l = str2.subSequence(str1.length()/2, str2.length()).toString();
        String tempr = Long.toHexString(Long.parseLong(str1r, 16) ^ Long.parseLong(str2r, 16));
        String templ = Long.toHexString(Long.parseLong(str1l, 16) ^ Long.parseLong(str2l, 16));
        String s = "";
        for(int i=0;i<8-templ.length();i++){
            s += "0";
        }
        s += templ;
        for(int i=0;i<8-tempr.length();i++){
            s += "0";
        }
        s += tempr;
        return s;
    }

    private static String encryption_round(String text, String sub_key){
        String left_part = text.subSequence(0, text.length()/2).toString();
        String right_part = text.subSequence(text.length()/2, text.length()).toString();

        return xor_hex_64bit_2(left_part, round.round_func(sub_key, right_part)) + right_part;
    }

    // private static String decryption_round(String text, String sub_key){
    //     String left_part = text.subSequence(0, text.length()/2).toString();
    //     String right_part = text.subSequence(text.length()/2, text.length()).toString();
    //
    //     return xor_hex_64bit_2(right_part, round.round_func(sub_key, left_part)) + left_part;
    // }

    public static String encryption_func(String plainText, String key){
        
        // subkey generation
        key_controller kk = new key_controller(key);
        String[] keys = kk.round_keys;

        // encryption rounds
        for(int i=0;i<16;i++){
            plainText = encryption_round(plainText, keys[i]);
            String left_part = plainText.subSequence(0, plainText.length()/2).toString();
            String right_part = plainText.subSequence(plainText.length()/2, plainText.length()).toString();
            plainText = right_part + left_part;
        }

        // after the last round there is no need for swaping the right and left part, so we just undo it
        String left_part = plainText.subSequence(0, plainText.length()/2).toString();
        String right_part = plainText.subSequence(plainText.length()/2, plainText.length()).toString();
        plainText = right_part + left_part;

        return plainText;
    }

    public static String decryption_func(String cipherText, String key){
        // subkey generation
        key_controller kk = new key_controller(key);
        String[] keys = kk.round_keys;

        // decryption rounds
        for(int i=0;i<16;i++){
            cipherText = encryption_round(cipherText, keys[15-i]);
            String left_part = cipherText.subSequence(0, cipherText.length()/2).toString();
            String right_part = cipherText.subSequence(cipherText.length()/2, cipherText.length()).toString();
            cipherText = right_part + left_part;
        }

        // after the last round there is no need for swaping the right and left part, so we just undo it
        String left_part = cipherText.subSequence(0, cipherText.length()/2).toString();
        String right_part = cipherText.subSequence(cipherText.length()/2, cipherText.length()).toString();
        cipherText = right_part + left_part;
        
        return cipherText;
    }

}
