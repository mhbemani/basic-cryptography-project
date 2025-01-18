package coco_128;
public class round {

    public static String round_func(String key ,String plainText){
        return matrix_multiplication(key_xor_and_sBox(key, plainText));
    }

    private static String xor_hex_8bit_2(String str1, String str2){
        String temp = Integer.toHexString(Integer.parseInt(str1, 16) ^ Integer.parseInt(str2, 16));
        if(temp.length()==1){
            return "0"+temp;
        }else return temp;
    }

    private static String[] key_xor_and_sBox(String key, String plainText){
        int[] sBox_output = new int[8];
        sBox_output[0] = s_boxes.sbox1(Integer.parseInt(xor_hex_8bit_2(""+key.subSequence(14, 16), ""+plainText.subSequence(0, 2)), 16));
        sBox_output[1] = s_boxes.sbox2(Integer.parseInt(xor_hex_8bit_2(""+key.subSequence(12, 14), ""+plainText.subSequence(2, 4)), 16));
        sBox_output[2] = s_boxes.sbox3(Integer.parseInt(xor_hex_8bit_2(""+key.subSequence(10, 12), ""+plainText.subSequence(4, 6)), 16));
        sBox_output[3] = s_boxes.sbox4(Integer.parseInt(xor_hex_8bit_2(""+key.subSequence(8, 10), ""+plainText.subSequence(6, 8)), 16));

        sBox_output[4] = s_boxes.sbox2(Integer.parseInt(xor_hex_8bit_2(""+key.subSequence(6, 8), ""+plainText.subSequence(8, 10)), 16));
        sBox_output[5] = s_boxes.sbox3(Integer.parseInt(xor_hex_8bit_2(""+key.subSequence(4, 6), ""+plainText.subSequence(10, 12)), 16));
        sBox_output[6] = s_boxes.sbox4(Integer.parseInt(xor_hex_8bit_2(""+key.subSequence(2, 4), ""+plainText.subSequence(12, 14)), 16));
        sBox_output[7] = s_boxes.sbox1(Integer.parseInt(xor_hex_8bit_2(""+key.subSequence(0, 2), ""+plainText.subSequence(14, 16)), 16));
        return dec_to_binary(sBox_output);
    }

    private static String[] dec_to_binary(int[] arr){
        String[] a = new String[8];
        for(int i=0;i<8; i++){
            String temp =""+ Integer.parseInt(Integer.toBinaryString(arr[i]));
            a[i] = "";
            for(int j=0; j<8-temp.length();j++){
                a[i] += "0";
            }
            a[i] += ""+ Integer.parseInt(Integer.toBinaryString(arr[i]));
        }
        return a;
    }

    private static String matrix_multiplication(String[] sBox_output){
        int[][] result = new int[8][8];
        for(int i=0;i<8;i++){
            for(int j=0;j<8;j++){
                int a = 0;
                for(int k=0;k<8;k++){
                    a += round_matrix[i][k] * Integer.parseInt(""+sBox_output[k].charAt(j));
                }
                result[i][j] = a%2;
            }
        }

        String output = "";
        for(int i=0;i<8;i++){
            String a = "";
            for(int j=0;j<8;j++){
                a += ""+result[i][j];
            }
            if(a.equals("00000000")){
                output += "00";
            }else{
                if(a.subSequence(0, 4) == "0000"){
                    output += "0" + Integer.toHexString(Integer.parseInt(a, 2));
                }else{
                    output += Integer.toHexString(Integer.parseInt(a, 2));
                }
            }
        }
        return output;
    }

    private static int[][] round_matrix = {
        {0, 1, 1, 1, 1, 0, 0, 1},
        {1, 0, 1, 1, 1, 1, 0, 0},
        {1, 1, 0, 1, 0, 1, 1, 0},
        {1, 1, 1, 0, 0, 0, 1, 1},
        {0, 1, 1, 1, 1, 1, 1, 0},
        {1, 0, 1, 1, 0, 1, 1, 1},
        {1, 1, 0, 1, 1, 0, 1, 1},
        {1, 1, 1, 0, 1, 1, 0, 1}
    };
}
