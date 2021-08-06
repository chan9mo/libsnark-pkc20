package java_test;

import java.math.BigInteger;
public class DecryptMessage {
    static BigInteger rho = new BigInteger("204444782122713504954636029222746100201332865755450300886921118968015889151");
    static Curve25519 EC_G = new Curve25519("16fd271ae0ad87ddae03044ac6852ee1d2ac024d42cff099c50ea7510d2a70a5", "291d2a8217f35195cb3f45acde062e1709c7fdc7b1fe623c0a27021ae5446310", false);
    //
    static Curve25519 EC_V = new Curve25519("2641a4d5bde35125e98f908661bb98d1d72f7c83556a0414b3bee3cd38761b2", "1457f1b03064bef2ec146abe368efac747e567c13e88383a5f480b33c0a88ea4", false);
    static Curve25519 EC_W = new Curve25519("209a59a35e54849c48d8d1696a8d5d5a98313ad92b091238bba960aa45f24934", "2b7778bcff02c32b97434e7beb39e64277022f0fa84607812ab3604038b83f33", false);

    public static void main(String[] args)
    {
        int number_of_people = 5000;
        long t1_start, t1_end;
        long t2_start, t2_end;
        Curve25519[] EC_msg = new Curve25519[15];
        BigInteger[] msg_guess = new BigInteger[15];

        t1_start = System.currentTimeMillis();
        for(int i = 0; i<15; i++)
        {
            msg_guess[i] = BigInteger.ZERO;
            msg_guess[i] = msg_guess[i].setBit(i*16);
            EC_msg[i] = EC_G.mul(msg_guess[i]);
        }
        t1_end = System.currentTimeMillis() - t1_start;

        t2_start = System.currentTimeMillis();
        Curve25519 Vsum=null, Wsum=null, EC_Vrho=null;
        BigInteger Msg_sum = BigInteger.ZERO;
        for(int j = 0; j<number_of_people; j++){
            EC_Vrho = EC_V.mul(rho); //todo: read V and caculate V^rho
            for(int i = 0; i<15; i++)
            {
                Curve25519 new_W = (EC_Vrho).add(EC_msg[i]);
                if(new_W.equals(EC_W)){
                
                    Vsum = Vsum == null ? EC_V : Vsum.add(EC_V);
                    Wsum = Wsum == null ? EC_W : Wsum.add(EC_W);
                    Msg_sum = Msg_sum.add(msg_guess[i]);
                }
            }
        }
        t2_end = System.currentTimeMillis() - t2_start;

        System.out.println("time spend: "+ t1_end + " "+ t2_end);
        System.out.println("   Vsum: " + Vsum.getPoint().toString(16));
        System.out.println("   Wsum: " + Wsum.getPoint().toString(16));
        System.out.println("Msg_sum: " + Msg_sum.toString(16));
    }
}