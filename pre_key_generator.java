package coco_128;
public abstract class pre_key_generator {

    private static String[] sub_keys = new String[16];
    
    static String xor_hex_8bit_6(String str1, String str2, String str3, String str4, String str5, String str6){
        String temp = Integer.toHexString(Integer.parseInt(str1, 16) ^ Integer.parseInt(str2, 16) ^ 
        Integer.parseInt(str3, 16) ^ Integer.parseInt(str4, 16) ^ 
        Integer.parseInt(str5, 16) ^ Integer.parseInt(str6, 16));
        if(temp.length()==1){
            return "0"+temp;
        }else return temp;
    }

    // the input key has assumed to be in HEX format
    static String pre_key_1(String key){
        
        String sub_key_0 = key.substring(0,2);
        String sub_key_1 = key.substring(2,4);
        String sub_key_2 = key.substring(4,6);
        String sub_key_3 = key.substring(6,8);
        String sub_key_4 = key.substring(8,10);
        String sub_key_5 = key.substring(10,12);
        String sub_key_6 = key.substring(12,14);
        String sub_key_7 = key.substring(14,16);
        String sub_key_8 = key.substring(16,18);
        String sub_key_9 = key.substring(18,20);
        String sub_key_10 = key.substring(20,22);
        String sub_key_11 = key.substring(22,24);
        String sub_key_12 = key.substring(24,26);
        String sub_key_13 = key.substring(26,28);
        String sub_key_14 = key.substring(28,30);
        String sub_key_15 = key.substring(30,32);

        // making the first quarter of the output
        String output_key = xor_hex_8bit_6(sub_key_0, 
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_13, 16)).subSequence(0, 2)+"",
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_15, 16)).subSequence(0, 2)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_12, 16)).subSequence(0, 2)+"",
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_14, 16)).subSequence(0, 2)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_8, 16)).subSequence(0, 2)+""
        );
        output_key += xor_hex_8bit_6(sub_key_1, 
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_13,16)).subSequence(2, 4)+"",
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_15, 16)).subSequence(2, 4)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_12, 16)).subSequence(2, 4)+"",
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_14, 16)).subSequence(2, 4)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_8, 16)).subSequence(2, 4)+""
        );
        output_key += xor_hex_8bit_6(sub_key_2, 
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_13, 16)).subSequence(4, 6)+"",
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_15, 16)).subSequence(4, 6)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_12, 16)).subSequence(4, 6)+"",
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_14, 16)).subSequence(4, 6)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_8, 16)).subSequence(4, 6)+""
        );
        output_key += xor_hex_8bit_6(sub_key_3, 
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_13, 16)).subSequence(6, 8)+"",
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_15, 16)).subSequence(6, 8)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_12, 16)).subSequence(6, 8)+"",
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_14, 16)).subSequence(6, 8)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_8, 16)).subSequence(6, 8)+""
        );
        // finally the first quarter of output is ready :)
        
        // now the second quarter
        output_key += xor_hex_8bit_6(sub_key_8, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(0, 2), 16)).subSequence(0, 2),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(4, 6)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(2, 4)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(6, 8)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_10, 16)).subSequence(0, 2)
        );
        output_key += xor_hex_8bit_6(sub_key_9, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(0, 2)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(4, 6)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(2, 4)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(6, 8)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_10, 16)).subSequence(2, 4)
        );
        output_key += xor_hex_8bit_6(sub_key_10, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(0, 2)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(4, 6)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(2, 4)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(6, 8)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_10, 16)).subSequence(4, 6)
        );
        output_key += xor_hex_8bit_6(sub_key_11, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(0, 2)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(4, 6)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(2, 4)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(6, 8)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_10, 16)).subSequence(6, 8)
        );

        //now the 3rd quarter
        output_key += xor_hex_8bit_6(sub_key_12, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(14, 16)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(12, 14)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(10, 12)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(8, 10)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_9, 16)).subSequence(0, 2)
        );
        output_key += xor_hex_8bit_6(sub_key_13, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(14, 16)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(12, 14)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(10, 12)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(8, 10)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_9, 16)).subSequence(2, 4)
        );
        output_key += xor_hex_8bit_6(sub_key_14, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(14, 16)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(12, 14)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(10, 12)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(8, 10)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_9, 16)).subSequence(4, 6)
        );
        output_key += xor_hex_8bit_6(sub_key_15, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(14, 16)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(12, 14)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(10, 12)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(8, 10)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_9, 16)).subSequence(6, 8)
        );

        //now the 4th quarter
        output_key += xor_hex_8bit_6(sub_key_4, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(20, 22)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(18, 20)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(22, 24)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(16, 18)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_11, 16)).subSequence(0, 2)
        );
        output_key += xor_hex_8bit_6(sub_key_5, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(20, 22)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(18, 20)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(22, 24)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(16, 18)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_11, 16)).subSequence(2, 4)
        );
        output_key += xor_hex_8bit_6(sub_key_6, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(20, 22)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(18, 20)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(22, 24)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(16, 18)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_11, 16)).subSequence(4, 6)
        );
        output_key += xor_hex_8bit_6(sub_key_7, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(20, 22)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(18, 20)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(22, 24)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(16, 18)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_11, 16)).subSequence(6, 8)
        );
        // now the output is ready for the pre_key_2
        // the output is a 32bit HEX number in string format

        return output_key;

    };

    static String pre_key_2(String key){
        String sub_key_0 = key.substring(0,2);
        String sub_key_1 = key.substring(2,4);
        String sub_key_2 = key.substring(4,6);
        String sub_key_3 = key.substring(6,8);
        String sub_key_4 = key.substring(8,10);
        String sub_key_5 = key.substring(10,12);
        String sub_key_6 = key.substring(12,14);
        String sub_key_7 = key.substring(14,16);
        String sub_key_8 = key.substring(16,18);
        String sub_key_9 = key.substring(18,20);
        String sub_key_10 = key.substring(20,22);
        String sub_key_11 = key.substring(22,24);
        String sub_key_12 = key.substring(24,26);
        String sub_key_13 = key.substring(26,28);
        String sub_key_14 = key.substring(28,30);
        String sub_key_15 = key.substring(30,32);

        // making the first quarter of the output
        String output_key = xor_hex_8bit_6(sub_key_8, 
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_5, 16)).subSequence(0, 2)+"",
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_7, 16)).subSequence(0, 2)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_4, 16)).subSequence(0, 2)+"",
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_6, 16)).subSequence(0, 2)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_0, 16)).subSequence(0, 2)+""
        );
        output_key += xor_hex_8bit_6(sub_key_9, 
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_5,16)).subSequence(2, 4)+"",
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_7, 16)).subSequence(2, 4)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_4, 16)).subSequence(2, 4)+"",
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_6, 16)).subSequence(2, 4)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_0, 16)).subSequence(2, 4)+""
        );
        output_key += xor_hex_8bit_6(sub_key_10, 
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_5, 16)).subSequence(4, 6)+"",
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_7, 16)).subSequence(4, 6)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_4, 16)).subSequence(4, 6)+"",
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_6, 16)).subSequence(4, 6)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_0, 16)).subSequence(4, 6)+""
        );
        output_key += xor_hex_8bit_6(sub_key_11, 
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_5, 16)).subSequence(6, 8)+"",
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_7, 16)).subSequence(6, 8)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_4, 16)).subSequence(6, 8)+"",
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_6, 16)).subSequence(6, 8)+"",
        ""+s_boxes.sbox7(Integer.parseInt(sub_key_0, 16)).subSequence(6, 8)+""
        );
        // finally the first quarter of output is ready :)

        // now the second quarter
        output_key += xor_hex_8bit_6(sub_key_0, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(0, 2), 16)).subSequence(0, 2),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(4, 6)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(2, 4)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(6, 8)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_2, 16)).subSequence(0, 2)
        );
        output_key += xor_hex_8bit_6(sub_key_1, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(0, 2)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(4, 6)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(2, 4)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(6, 8)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_2, 16)).subSequence(2, 4)
        );
        output_key += xor_hex_8bit_6(sub_key_2, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(0, 2)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(4, 6)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(2, 4)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(6, 8)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_2, 16)).subSequence(4, 6)
        );
        output_key += xor_hex_8bit_6(sub_key_3, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(0, 2)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(4, 6)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(2, 4)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(6, 8)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox8(Integer.parseInt(sub_key_2, 16)).subSequence(6, 8)
        );

        //now the 3rd quarter
        output_key += xor_hex_8bit_6(sub_key_4, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(14, 16)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(12, 14)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(10, 12)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(8, 10)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_1, 16)).subSequence(0, 2)
        );
        output_key += xor_hex_8bit_6(sub_key_5, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(14, 16)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(12, 14)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(10, 12)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(8, 10)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_1, 16)).subSequence(2, 4)
        );
        output_key += xor_hex_8bit_6(sub_key_6, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(14, 16)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(12, 14)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(10, 12)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(8, 10)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_1, 16)).subSequence(4, 6)
        );
        output_key += xor_hex_8bit_6(sub_key_7, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(14, 16)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(12, 14)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(10, 12)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(8, 10)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox5(Integer.parseInt(sub_key_1, 16)).subSequence(6, 8)
        );

        //now the 4th quarter
        output_key += xor_hex_8bit_6(sub_key_12, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(20, 22)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(18, 20)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(22, 24)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(16, 18)+"", 16)).subSequence(0, 2),
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_11, 16)).subSequence(0, 2)
        );
        output_key += xor_hex_8bit_6(sub_key_13, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(20, 22)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(18, 20)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(22, 24)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(16, 18)+"", 16)).subSequence(2, 4),
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_11, 16)).subSequence(2, 4)
        );
        output_key += xor_hex_8bit_6(sub_key_14, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(20, 22)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(18, 20)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(22, 24)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(16, 18)+"", 16)).subSequence(4, 6),
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_11, 16)).subSequence(4, 6)
        );
        output_key += xor_hex_8bit_6(sub_key_15, 
        ""+s_boxes.sbox5(Integer.parseInt(""+output_key.subSequence(20, 22)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox6(Integer.parseInt(""+output_key.subSequence(18, 20)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox7(Integer.parseInt(""+output_key.subSequence(22, 24)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox8(Integer.parseInt(""+output_key.subSequence(16, 18)+"", 16)).subSequence(6, 8),
        ""+s_boxes.sbox6(Integer.parseInt(sub_key_11, 16)).subSequence(6, 8)
        );
        // now the output is ready for the pre_key_2
        // the output is a 32bit HEX number in string format

        return output_key;
    };

}
