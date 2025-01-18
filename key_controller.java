package coco_128;
public class key_controller {

    // key is 32 bit in HEX

    String[] round_keys = new String[16];
    
    key_controller(String key){
        // round 1
        key = pre_key_generator.pre_key_1(key);
        round_keys[0] = key_generator.key_gen_1_1(key);
        round_keys[1] = key_generator.key_gen_1_2(key);
        key = pre_key_generator.pre_key_2(key);
        round_keys[2] = key_generator.key_gen_2_1(key);
        round_keys[3] = key_generator.key_gen_2_2(key);

        // round 2
        key = pre_key_generator.pre_key_1(key);
        round_keys[4] = key_generator.key_gen_3_1(key);
        round_keys[5] = key_generator.key_gen_3_2(key);
        key = pre_key_generator.pre_key_2(key);
        round_keys[6] = key_generator.key_gen_4_1(key);
        round_keys[7] = key_generator.key_gen_4_2(key);

        // round 3
        key = pre_key_generator.pre_key_1(key);
        round_keys[8] = key_generator.key_gen_1_1(key);
        round_keys[9] = key_generator.key_gen_1_2(key);
        key = pre_key_generator.pre_key_2(key);
        round_keys[10] = key_generator.key_gen_2_1(key);
        round_keys[11] = key_generator.key_gen_2_2(key);

        // round 4
        key = pre_key_generator.pre_key_1(key);
        round_keys[12] = key_generator.key_gen_3_1(key);
        round_keys[13] = key_generator.key_gen_3_2(key);
        key = pre_key_generator.pre_key_2(key);
        round_keys[14] = key_generator.key_gen_4_1(key);
        round_keys[15] = key_generator.key_gen_4_2(key);
    }
    
    public String[] return_keys(){
        return round_keys;
    }
}
