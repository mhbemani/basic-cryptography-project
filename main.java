package coco_128;
public class main {
    public static void main(String[] args) {
        String text = "ggggggggg4";
        String key = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
        String a = decryption_methodes.CBC(encryption_methods.CBC(text, key), key);
        System.out.println(a);

        
        
        
    }
}   