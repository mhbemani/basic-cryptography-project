package asymmetric;

import java.math.BigInteger;
import java.util.Random;

// miller rabin                             ..done
// finding prime num                        ..done
// impliment RSA key generation             ..done
// impliment DSA key generation             ..done
public class prime {
    //// find a prime number -->  with max_bit_length( 128 )
    public BigInteger findPrime(int bits){
        
        BigInteger num = randomNumGenerator(bits);
        while(miller_rabin_algo(num, bits) == false){
            num = randomNumGenerator(bits);
        }
        return num;
    }

    public BigInteger randomNumGenerator(int bits){
        return new BigInteger(bits, new Random());
    }

    boolean miller_rabin_algo(BigInteger p, int bits){    ///    NOT TESTED YET
        if(p.mod(BigInteger.TWO).equals(BigInteger.ZERO)) return false;
        //  we ahve to find u and r as follows:
        //  p - 1 = 2^u * r

        p = p.subtract(BigInteger.ONE); //p = p-1
        int uInt = 2;
        BigInteger u = BigInteger.valueOf(uInt);

        while(true){
            u = BigInteger.TWO.pow(uInt);
            if(p.mod(u).equals(BigInteger.ZERO)){
                uInt++;
                u = BigInteger.TWO.pow(uInt);
            }else{
                uInt--;
                u = BigInteger.TWO.pow(uInt);
                break;
            }
            // System.out.println("tttttttt");
        }
        BigInteger r = p.divide(u);

        // now p u and r are ready
        boolean primeLikly = false;
        for(int i=0;i<3;i++){
            primeLikly = false;
            
            BigInteger rand = new BigInteger(p.bitLength()-1, new Random()); // -1 makes sure that the random num < p
            BigInteger z = rand.modPow(r, p.add(BigInteger.ONE));
            if(z.equals(BigInteger.ONE)){
                primeLikly = true;
                // continue;
            }
            for(int j=0;j<uInt-1;j++){
                z = z.modPow(BigInteger.TWO, p.add(BigInteger.ONE));
                if(z.equals(p)){
                    primeLikly = true;
                    break;
                }
            }
            if(primeLikly == false){
                break;
            }
        }
        return primeLikly;
    }

    //// RSA key generation
    // not all of them should be public :/
    public BigInteger RSA_private_key ;
    public BigInteger RSA_public_key ;
    public BigInteger modulo ;
    public BigInteger RSA_q ;
    public BigInteger RSA_p ;

    BigInteger phi;
    public void RSA_key_generator(){

        do{
            RSA_q = findPrime(1024);
            RSA_p = findPrime(1024);
            modulo = RSA_q.multiply(RSA_p);
        }while(modulo.bitLength()!=2048);
        
        phi = (RSA_p.subtract(BigInteger.ONE)).multiply(RSA_q.subtract(BigInteger.ONE));
        RSA_private_key = findPrime(1024); // changex 128 into 1024
        while(!RSA_private_key.gcd(phi).equals(BigInteger.ONE) || RSA_private_key.compareTo(phi)>=0){ // added compareson
            RSA_private_key = findPrime(1024);
        }
        RSA_public_key = RSA_private_key.modInverse(phi);
        System.out.println(RSA_public_key); ////////////////////////////////////
    }
    
    public BigInteger DSA_p;
    public BigInteger DSA_q;
    public BigInteger DSA_b;
    public BigInteger DSA_a;
    public BigInteger DSA_d;
    public void DSA_key_generator(){
        // this block generates the q and p
        boolean flag=false;
        do{
            do{
                DSA_q = findPrime(160);
            }while(DSA_q.bitLength()!=160);
    
            for(int i=0;i<4096;i++){
                BigInteger temp;
                do{
                    temp = new BigInteger(1024, new Random());
                }while(temp.bitLength()!=1024);
                BigInteger temp0 = temp.mod(DSA_q.multiply(BigInteger.TWO));
                DSA_p = temp.subtract(temp0).add(BigInteger.ONE);
                if(miller_rabin_algo(DSA_p, 0)) {
                    flag = true;
                    break;
                }
            }
        }while (!flag);
        // this block generates the a
        //// assume this block works properly
        do{
            DSA_a = new BigInteger(1024, new Random());
            DSA_a = DSA_a.modPow((DSA_p.subtract(BigInteger.ONE)).divide(DSA_q), DSA_p);
        }while(DSA_a.compareTo(BigInteger.ONE)<=0);
        // this block generates the d
        do{
            DSA_d = new BigInteger(160, new Random());
        }while(DSA_d.compareTo(DSA_q)>=0);
        // this block generates the b
        DSA_b = DSA_a.modPow(DSA_d, DSA_p);
        

        
    }

        
}
