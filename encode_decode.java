package coco_128;
public class encode_decode {

    static String encoding_func(String s){

        // adding the padding to meet the requaiered length
        for(int i=0;i<s.length()%16;i++){
            s += "&";
        }

        // encoding the plainText into numbers before encryption
        String encoded_text = "";
        for(int i=0;i<s.length();i++){
            if(Integer.parseInt(encoding_sbox(s.charAt(i))) < 16){
                encoded_text += "0" + Integer.toHexString(Integer.parseInt(encoding_sbox(s.charAt(i))));
            }else{
                encoded_text += Integer.toHexString(Integer.parseInt(encoding_sbox(s.charAt(i))));
            }
        }
        return encoded_text;
        // the output is in HEX format
    }

    static String decoding_func(String s){
        String decoded_text = "";
        for(int i=0 ; i+2 <= s.length() ; i+=2){
            decoded_text += decode_sbox(Integer.parseInt(""+s.subSequence(i, i+2), 16));
        }
        while("&".equals(decoded_text.charAt(decoded_text.length()-1)+"")){
            decoded_text = decoded_text.subSequence(0, decoded_text.length()-1).toString();
        }
        return decoded_text;
    }

    private static String decode_sbox(int num){
        String b = "";
        switch (num) {
            case 0:
                b = " ";
                break;
            case 1:
                b = "0";
                break;
            case 2:
                b = "1";
                break;
            case 3:
                b = "2";
                break;
            case 4:
                b = "3";
                break;
            case 5:
                b = "4";
                break;
            case 6:
                b = "5";
                break;
            case 7:
                b = "6";
                break;
            case 8:
                b = "7";
                break;
            case 9:
                b = "8";
                break;
            case 10:
                b = "9";
                break;
            case 11:
                b = "a";
                break;
            case 12:
                b = "b";
                break;
            case 13:
                b = "c";
                break;
            case 14:
                b = "d";
                break;
            case 15:
                b = "e";
                break;
            case 16:
                b = "f";
                break;
            case 17:
                b = "g";
                break;
            case 18:
                b = "h";
                break;
            case 19:
                b = "i";
                break;
            case 20:
                b = "j";
                break;
            case 21:
                b = "k";
                break;
            case 22:
                b = "l";
                break;
            case 23:
                b = "m";
                break;
            case 24:
                b = "n";
                break;
            case 25:
                b = "o";
                break;
            case 26:
                b = "p";
                break;
            case 27:
                b = "q";
                break;
            case 28:
                b = "r";
                break;
            case 29:
                b = "s";
                break;
            case 30:
                b = "t";
                break;
            case 31:
                b = "u";
                break;
            case 32:
                b = "v";
                break;
            case 33:
                b = "w";
                break;
            case 34:
                b = "x";
                break;
            case 35:
                b = "y";
                break;
            case 36:
                b = "z";
                break;
            case 37:
                b = "A";
                break;
            case 38:
                b = "B";
                break;
            case 39:
                b = "C";
                break;
            case 40:
                b = "D";
                break;
            case 41:
                b = "E";
                break;
            case 42:
                b = "F";
                break;
            case 43:
                b = "G";
                break;
            case 44:
                b = "H";
                break;
            case 45:
                b = "I";
                break;
            case 46:
                b = "J";
                break;
            case 47:
                b = "K";
                break;
            case 48:
                b = "L";
                break;
            case 49:
                b = "M";
                break;
            case 50:
                b = "N";
                break;
            case 51:
                b = "O";
                break;
            case 52:
                b = "P";
                break;
            case 53:
                b = "Q";
                break;
            case 54:
                b = "R";
                break;
            case 55:
                b = "S";
                break;
            case 56:
                b = "T";
                break;
            case 57:
                b = "U";
                break;
            case 58:
                b = "V";
                break;
            case 59:
                b = "W";
                break;
            case 60:
                b = "X";
                break;
            case 61:
                b = "Y";
                break;
            case 62:
                b = "Z";
                break;
            case 63:
                b = "!";
                break;
            case 64:
                b = "@";
                break;
            case 65:
                b = "#";
                break;
            case 66:
                b = "$";
                break;
            case 67:
                b = "%";
                break;
            case 68:
                b = "^";
                break;
            case 69:
                b = "&";
                break;
            case 70:
                b = "*";
                break;
            case 71:
                b = "(";
                break;
            case 72:
                b = ")";
                break;
            case 73:
                b = "-";
                break;
            case 74:
                b = "+";
                break;
            case 75:
                b = ".";
                break;
            case 76:
                b = ",";
                break;
            default:
                b = "77";
                break;
        }
        return b;
    }

    private static String encoding_sbox(char a){
        String  b= ""+a;
        switch (b) {
            case " ":
                b = "0";
                break;
            case "0":
                b = "1";
                break;
            case "1":
                b = "2";
                break;
            case "2":
                b = "3";
                break;
            case "3":
                b = "4";
                break;
            case "4":
                b = "5";
                break;
            case "5":
                b = "6";
                break;
            case "6":
                b = "7";
                break;
            case "7":
                b = "8";
                break;
            case "8":
                b = "9";
                break;
            case "9":
                b = "10";
                break;
            case "a":
                b = "11";
                break;
            case "b":
                b = "12";
                break;
            case "c":
                b = "13";
                break;
            case "d":
                b = "14";
                break;
            case "e":
                b = "15";
                break;
            case "f":
                b = "16";
                break;
            case "g":
                b = "17";
                break;
            case "h":
                b = "18";
                break;
            case "i":
                b = "19";
                break;
            case "j":
                b = "20";
                break;
            case "k":
                b = "21";
                break;
            case "l":
                b = "22";
                break;
            case "m":
                b = "23";
                break;
            case "n":
                b = "24";
                break;
            case "o":
                b = "25";
                break;
            case "p":
                b = "26";
                break;
            case "q":
                b = "27";
                break;
            case "r":
                b = "28";
                break;
            case "s":
                b = "29";
                break;
            case "t":
                b = "30";
                break;
            case "u":
                b = "31";
                break;
            case "v":
                b = "32";
                break;
            case "w":
                b = "33";
                break;
            case "x":
                b = "34";
                break;
            case "y":
                b = "35";
                break;
            case "z":
                b = "36";
                break;
            case "A":
                b = "37";
                break;
            case "B":
                b = "38";
                break;
            case "C":
                b = "39";
                break;
            case "D":
                b = "40";
                break;
            case "E":
                b = "41";
                break;
            case "F":
                b = "42";
                break;
            case "G":
                b = "43";
                break;
            case "H":
                b = "44";
                break;
            case "I":
                b = "45";
                break;
            case "J":
                b = "46";
                break;
            case "K":
                b = "47";
                break;
            case "L":
                b = "48";
                break;
            case "M":
                b = "49";
                break;
            case "N":
                b = "50";
                break;
            case "O":
                b = "51";
                break;
            case "P":
                b = "52";
                break;
            case "Q":
                b = "53";
                break;
            case "R":
                b = "54";
                break;
            case "S":
                b = "55";
                break;
            case "T":
                b = "56";
                break;
            case "U":
                b = "57";
                break;
            case "V":
                b = "58";
                break;
            case "W":
                b = "59";
                break;
            case "X":
                b = "60";
                break;
            case "Y":
                b = "61";
                break;
            case "Z":
                b = "62";
                break;
            case "!":
                b = "63";
                break;
            case "@":
                b = "64";
                break;
            case "#":
                b = "65";
                break;
            case "$":
                b = "66";
                break;
            case "%":
                b = "67";
                break;
            case "^":
                b = "68";
                break;
            case "&":
                b = "69";
                break;
            case "*":
                b = "70";
                break;
            case "(":
                b = "71";
                break;
            case ")":
                b = "72";
                break;
            case "-":
                b = "73";
                break;
            case "+":
                b = "74";
                break;
            case ".":
                b = "75";
                break;
            case ",":
                b = "76";
                break;
            default:
                b = "77";
                break;
        }
        
        return b;
    }

}
