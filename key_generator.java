package coco_128;
public abstract class key_generator {
    
    static String xor_hex_8bit_5(String str1, String str2, String str3, String str4, String str5){
        String temp = Integer.toHexString(Integer.parseInt(str1, 16) ^ Integer.parseInt(str2, 16) ^ 
        Integer.parseInt(str3, 16) ^ Integer.parseInt(str4, 16) ^ Integer.parseInt(str5, 16));
        if(temp.length()==1){
            return "0"+temp;
        }else return temp;
    }

    static String key_gen_1_1(String key){
        //first part before the OR
        String xor_1 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(0, 2)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(2, 4)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(4, 6)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(6, 8)
        );
        // second part before the OR
        String xor_2 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(0, 2)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(2, 4)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(4, 6)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(6, 8)
        );
        // both sides are ready for the OR section
        // String result = "";
        // for(int i=0; i<xor_1.length();i++){
        //     result +=  xor_1.charAt(i) | xor_2.charAt(i);
        // }
        // return result;
        xor_1 += xor_2;
        return xor_1;

    };

    static String key_gen_1_2(String key){
        //first part before the OR
        String xor_1 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(0, 2)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(2, 4)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(4, 6)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(6, 8)
        );
        // second part before the OR
        String xor_2 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(0, 2)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(2, 4)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(4, 6)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(6, 8)
        );
        // both sides are ready for the OR section
        // String result = "";
        // for(int i=0; i<xor_1.length();i++){
        //     result +=  xor_1.charAt(i) | xor_2.charAt(i);
        // }
        // return result;
        xor_1 += xor_2;
        return xor_1;
    };

    static String key_gen_2_1(String key){
        //first part before the OR
        String xor_1 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(0, 2)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(2, 4)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(4, 6)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(6, 8)
        );
        // second part before the OR
        String xor_2 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(0, 2)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(2, 4)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(4, 6)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(6, 8)
        );
        // both sides are ready for the OR section
        // String result = "";
        // for(int i=0; i<xor_1.length();i++){
        //     result +=  xor_1.charAt(i) | xor_2.charAt(i);
        // }
        // return result;
        xor_1 += xor_2;
        return xor_1;
    };

    static String key_gen_2_2(String key){
        //first part before the OR
        String xor_1 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(0, 2)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(2, 4)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(4, 6)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(6, 8)
        );
        // second part before the OR
        String xor_2 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(0, 2)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(2, 4)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(4, 6)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(6, 8)
        );
        // both sides are ready for the OR section
        // String result = "";
        // for(int i=0; i<xor_1.length();i++){
        //     result +=  xor_1.charAt(i) | xor_2.charAt(i);
        // }
        // return result;
        xor_1 += xor_2;
        return xor_1;
    };

    static String key_gen_3_1(String key){
        //first part before the OR
        String xor_1 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(0, 2)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(2, 4)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(4, 6)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(6, 8)
        );
        // second part before the OR
        String xor_2 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(0, 2)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(2, 4)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(4, 6)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(6, 8)
        );
        // both sides are ready for the OR section
        // String result = "";
        // for(int i=0; i<xor_1.length();i++){
        //     result +=  xor_1.charAt(i) | xor_2.charAt(i);
        // }
        // return result;
        xor_1 += xor_2;
        return xor_1;
    };

    static String key_gen_3_2(String key){
        //first part before the OR
        String xor_1 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(0, 2)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(2, 4)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(4, 6)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(6, 8)
        );
        // second part before the OR
        String xor_2 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(0, 2)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(2, 4)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(4, 6)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(6, 8)
        );
        // both sides are ready for the OR section
        // String result = "";
        // for(int i=0; i<xor_1.length();i++){
        //     result +=  xor_1.charAt(i) | xor_2.charAt(i);
        // }
        // return result;
        xor_1 += xor_2;
        return xor_1;
    };

    static String key_gen_4_1(String key){
        //first part before the OR
        String xor_1 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(0, 2)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(2, 4)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(4, 6)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(18, 20)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(12, 14)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(6, 8)
        );
        // second part before the OR
        String xor_2 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(0, 2)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(2, 4)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(4, 6)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(20, 22)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(22, 24)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(10, 12)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(8, 10)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(14, 16)+"", 16)).subSequence(6, 8)
        );
        // both sides are ready for the OR section
        // String result = "";
        // for(int i=0; i<xor_1.length();i++){
        //     result +=  xor_1.charAt(i) | xor_2.charAt(i);
        // }
        // return result;
        xor_1 += xor_2;
        return xor_1;
    };

    static String key_gen_4_2(String key){
        //first part before the OR
        String xor_1 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(0, 2)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(2, 4)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(4, 6)
        );
        xor_1 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(24, 26)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(6, 8)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(4, 6)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(16, 18)+"", 16)).subSequence(6, 8)
        );
        // second part before the OR
        String xor_2 = xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(0, 2), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(0, 2)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(2, 4), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(2, 4)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(4, 6), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(4, 6)
        );
        xor_2 += xor_hex_8bit_5(
            ""+s_boxes.sbox5(Integer.parseInt(""+key.subSequence(28, 30)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox6(Integer.parseInt(""+key.subSequence(30, 32)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox7(Integer.parseInt(""+key.subSequence(2, 4)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(0, 2)+"", 16)).subSequence(6, 8), 
            ""+s_boxes.sbox8(Integer.parseInt(""+key.subSequence(26, 28)+"", 16)).subSequence(6, 8)
        );
        // both sides are ready for the OR section
        // String result = "";
        // for(int i=0; i<xor_1.length();i++){
        //     result +=  xor_1.charAt(i) | xor_2.charAt(i);
        // }
        // return result;
        xor_1 += xor_2;
        return xor_1;
    };

}
