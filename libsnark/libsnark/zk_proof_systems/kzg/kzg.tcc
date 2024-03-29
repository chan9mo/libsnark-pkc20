/** @file
*****************************************************************************

Implementation of Kate Polynomial Commitment for R1CS.

See kzg10.hpp .

*****************************************************************************
* @author     This file is part of libsnark, developed by SCIPR Lab
*             and contributors (see AUTHORS).
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#ifndef KZG_TCC_
#define KZG_TCC_

#include <iostream>

namespace libsnark {

template<typename ppT>
commitkey<ppT> kzg_setup(int t)
{
    libff::enter_block("Call to kzg_setup");

    /* Generate generator g, randomness a */
    libff::enter_block("Generator G, randomness A");

    libff::G1<ppT> generator = libff::G1<ppT>::random_element();

    libff::G2<ppT> generator2 = libff::G2<ppT>::random_element();  // why G2 together?: for the vefiryeval reduced_pairing computation

    libff::Fr<ppT> a = libff::Fr<ppT>::random_element();

    libff::leave_block("Generator G, randomness A");

    // libff::print_header("Generator G: for G1");
    // generator.print();

    // libff::print_header("Generator G: for G2");
    // generator2.print();
    // printf("\n");

    /* Generate t-SDH tuple : G1 */
    libff::enter_block("Generate t-SDH tuple: G1");

    libff::Fr<ppT> exp_a = libff::Fr<ppT>::one();

    libff::G1_vector<ppT> g1tuple(t+1); //(t) 초기화 이후 emplace_back 연산 모두 배열 삽입 연산으로 바꿔줘야 한다.
    g1tuple[0] = generator; // t-SDH = (g1, ...)
    // g1tuple[0].print();

    for(size_t i = 1; i < t + 1; i++)
    {
        exp_a = exp_a * a;
        g1tuple[i] = exp_a * generator;
        // g1tuple.emplace_back(exp_a * generator); //group element should be at right side always!! ALWAYS !!!!!
        // g1tuple[i].print();
    }

    libff::leave_block("Generate t-SDH tuple: G1");

    /* Generate t-SDH tuple : G2 */
    libff::enter_block("Generate t-SDH tuple: G2");

    libff::Fr<ppT> exp_a2 = libff::Fr<ppT>::one();

    libff::G2_vector<ppT> g2tuple(t+1);
    g2tuple[0] = generator2;
    // g2tuple[0].print();

    for(size_t i = 1; i < t + 1; i++)
    {
        exp_a2 = exp_a2 * a;
        g2tuple[i] = exp_a2 * generator2;
        // g2tuple.emplace_back(exp_a2 * generator2);
        // g2tuple[i].print();
    }

    libff::leave_block("Generate t-SDH tuple: G2");

    libff::leave_block("Generate t-SDH tuple");

    /* Output as a commitment key */
    libff::leave_block("Call to kzg_setup");

    commitkey<ppT> tuple = commitkey<ppT>(std::move(g1tuple), std::move(g2tuple));
    return tuple;

}

template<typename ppT>
libff::G1<ppT> kzg_commit(commitkey<ppT> &ck, libff::Fr_vector<ppT> &poly, int t)
{
    libff::enter_block("Call to kzg_commit");

    libff::enter_block("Commit at G1");

    libff::G1<ppT> temp = libff::G1<ppT>::zero();
    libff::G1<ppT> commit1 = libff::G1<ppT>::zero();

    for(size_t i = 1; i < t + 1; i++) {
        if(poly[t - i] == 0) {
            continue;
        }
        else {
            temp = poly[t - i] * ck.g1[i - 1];
            commit1 = temp + commit1;
        }
    }

    libff::leave_block("Commit at G1");

    // libff::enter_block("Commit at G2");

    // libff::G2<ppT> temp2 = libff::G2<ppT>::zero();
    // libff::G2<ppT> commit2 = libff::G2<ppT>::zero();

    // for(size_t i = 1; i < t + 1; i++) {
    //     if(poly[t-i] == 0) {
    //         continue;
    //     }
    //     else {
    //         temp2 = poly[t - i] * ck.g2[i - 1];
    //         commit2 = temp2 + commit2;
    //     }
    // }

    // libff::leave_block("Commit at G2");

    // libff::print_header("Commitment C");
    // commit1.print();
    // printf("\n");

    libff::leave_block("Call to kzg_commit");
    // commitment<ppT> result = commitment<ppT>(std::move(commit1), std::move(commit2));

    return commit1;
}

template<typename ppT>
witness<ppT> kzg_witness(commitkey<ppT> &ck, libff::Fr_vector<ppT> &poly, libff::Fr<ppT> &point, int t)
{
    libff::enter_block("Call to kzg_witness");
    int i;

    /* Evaluate Polynomial */
    libff::enter_block("Evaluate Polynomial");

    libff::Fr<ppT> eval = libff::Fr<ppT>::zero();
    libff::Fr<ppT> temp = libff::Fr<ppT>::one();

    for(i = 1; i < t + 1; i++) {
    eval += poly[t - i] * temp;
    temp *= point;
    }

    libff::leave_block("Evaluate Polynomial");

    libff::enter_block("Constant Update : poly(x) - poly(i)");

    poly[t - 1] = poly[t - 1] - eval;

    // libff::print_header("Evaluation, Updated Constant");

    // eval.print();
    // poly[t - 1].print();
    // printf("\n");

    libff::leave_block("Constant Update : poly(x) - poly(i)");


    /* Divisor: (x - point) */
    libff::enter_block("Compute Divisor[2]: stands for polynomial (x - point)");

    libff::Fr_vector<ppT> divisor(2);
    // divisor.emplace_back(convert<ppT>(1));
    divisor[0] = convert<ppT>(1);

    libff::Fr<ppT> minus = libff::Fr<ppT>::zero();
    minus = minus - point;
    divisor[1] = minus;

    // libff::print_header("Divisor[2]: stands for polynomial (x - point)");

    // divisor[0].print();
    // divisor[1].print();
    // printf("\n");

    libff::leave_block("compute divisor[2]: stands for polynomial (x - point)");

    //division Algorithm.
    libff::enter_block("Divide Algorithm: poly(x) - poly(i) / (x - i)");
    libff::Fr_vector<ppT> psi(t);

     for(i = 0; i < t - 1; i++) {
        psi[i] = poly[i];
        // psi.emplace_back(poly[i]);
        poly[i] = poly[i] - (psi[i] * divisor[0]);
        poly[i + 1] = poly[i + 1] - psi[i] * divisor[1];
        // psi[i].print();
    }

    // if(poly[t - 1] == 0) {
    //     libff::print_header("Division Success!");
    // } else {
    //     printf("division Fail. Abort.");
    // }

    libff::leave_block("Divide Algorithm: poly(x) - poly(i) / (x - i)");

    /* compute w = g ^ psi(a) */

    libff::enter_block("Compute w = g ^ psi(a): G1");

    libff::G1<ppT> temp1 = libff::G1<ppT>::zero();
    libff::G1<ppT> w1 = libff::G1<ppT>::zero();

    for(int i = 2; i < t + 1; i++) {
        if(psi[t - i] == 0) {
            continue;
        }
        else {
            temp1 = psi[t - i] * ck.g1[i - 2];
            w1 = temp1 + w1;
        }
    }

    // libff::print_header("witness w = g^psi: G1");

    // w1.print();

    libff::leave_block("Compute w = g ^ psi(a): G1");

    // libff::enter_block("Compute w = g ^ psi(a):G2");

    // libff::G2<ppT> temp2 = libff::G2<ppT>::zero();
    // libff::G2<ppT> w2 = libff::G2<ppT>::zero();

    // for(size_t i = 2; i < t + 1; i++) {
    //     if(psi[t-i] == 0) {
    //         continue;
    //     }
    //     else {
    //         temp2 = psi[t - i] * ck.g2[i - 2];
    //         w2 = temp2 + w2;
    //     }
    // }

    // // libff::print_header("witness w = g^psi: G2");

    // // w2.print();
    // // printf("\n");

    // libff::leave_block("Compute w = g ^ psi(a):G2");

    libff::leave_block("Call to kzg_witness");

    /* Output as a witness */
    // witness<ppT> wit = witness<ppT>(std::move(point), std::move(eval), std::move(w1), std::move(w2));
    witness<ppT> wit = witness<ppT>(std::move(point), std::move(eval), std::move(w1));
    return wit;
}

template<typename ppT>
libff::Fr<ppT> convert(int t)
{
    libff::Fr<ppT> result = libff::Fr<ppT>::zero();

    if(t > 0) {

    for(size_t i = 0; i < t; i++) {
        result += libff::Fr<ppT>::one();
    }

    } else if(t == 0) {
        
    } else if(t < 0) {
        for(size_t i = 0; i < (-t); i++) {
        result += -(libff::Fr<ppT>::one());
        }
    }
    return result;
}

template<typename ppT>
bool kzg_vfyeval(commitkey<ppT> &ck, libff::G1<ppT> &commit, witness<ppT> &witness)
{
    //symmetric Group, G, GT만 존재. (구현상으로는 G1으로 했기 때문에 G1, GT만 존재하는것으로..?)
    // g2 자리에 들어가는 건 g2원소로 만들어야 한다. G2용 generator를 만들어서 한번 계산해보도록.

    libff::enter_block("Call to kzg_vfyeval");

    /* LEFT SIDE: e(C, g) */
    libff::enter_block("Compute LEFT : e(C, g)");

    libff::GT<ppT> left1 = ppT::reduced_pairing(commit, ck.g2[0]); //either side does not matter.
    // libff::GT<ppT> left1_g2 = ppT::reduced_pairing(ck.g1[0], commit.g2);

    // libff::print_header("LEFT: e(Commit, generator)");
    // left1.print();
    // printf("\n\n");

    libff::leave_block("Compute LEFT : e(C, g)");

    /* RIGHT SIDE: e(w, g ^ (a-i)) * e(g ^ eval, g) */
    libff::enter_block("Compute RIGHT : e(w, g ^ (a-i)) * e(g ^ eval, g)");

    /*right1, 3: e(w, g ^ (a-i))*/
    libff::enter_block("Compute e(w, g ^ (a-i))");
    libff::Fr<ppT> zero = libff::Fr<ppT>::zero();

    /*g ^ (-i)*/
    libff::enter_block("Compute g ^ (-i)");

    libff::Fr<ppT> num = zero - witness.point;
    libff::G1<ppT> num1 = num * ck.g1[0];
    libff::G2<ppT> num2 = num * ck.g2[0];

    libff::leave_block("Compute g ^ (-i)");

    /* e(w, g ^ (- i) * g ^ a = g ^ (a - i)) */

    // libff::GT<ppT> right1_g2 = ppT::reduced_pairing(num1 + ck.g1[1], witness.w2);
    libff::GT<ppT> right1 = ppT::reduced_pairing(witness.w1, num2 + ck.g2[1]);

    // libff::print_header("e(w, g ^ (a-i))");
    libff::leave_block("Compute e(w, g ^ (a-i))");

    /* right2: e(g ^ eval, g) */
    libff::enter_block("Compute e(g ^ eval, g");

    libff::GT<ppT> right2 = ppT::reduced_pairing(witness.eval * ck.g1[0], ck.g2[0]); //eval which side? doesnt matter.
    // libff::GT<ppT> right2_g2 = ppT::reduced_pairing(ck.g1[0], witness.eval * ck.g2[0]);

    // libff::print_header(" e(g ^ eval, g)");
    libff::leave_block("Compute e(g ^ eval, g");

    /* RIGHT: e(w, g ^ (a-i)) * e(g ^ eval, g), */

    libff::GT<ppT> right = right1 * right2;
    libff::leave_block("Compute RIGHT : e(w, g ^ (a-i)) * e(g ^ eval, g)");

    // libff::print_header("RIGHT: e(w, g^a/g^i) * e(g^eval, g)");
    // right.print();

    libff::enter_block("Verification: LEFT =? RIGHT");
    bool verifyresult;

    if (left1 == right) {
        verifyresult = true;
        // libff::print_header("VERIFICATION ACCEPT!!");
    } else {
        verifyresult = false;
        // libff::print_header("VERIFICATION REJECT");
    }

    libff::leave_block("Verification: LEFT =? RIGHT");

    libff::leave_block("Call to kzg_vfyeval");

    // return verifyresult;
    return verifyresult;
}


// template<typename ppT>
// bool kzg_testvfy(commitkey<ppT> &ck, commitment<ppT> &commit, witness<ppT> &witness, libff::Fr_vector<ppT> &poly, int t)
// {
//     int i;
//     libff::print_header("1. e(w, g ^ (a-i)) * e(g ^ eval, g)");

//     libff::Fr<ppT> zero = libff::Fr<ppT>::zero();
//     libff::Fr<ppT> one = libff::Fr<ppT>::one();

//     //g ^ (-i)
//     libff::Fr<ppT> num = zero - witness.point;

//     //g ^ (-i) * g ^ a = g ^ (a - i)
//     libff::G1<ppT> num1 = num * ck.g1[0];
//     libff::G2<ppT> num2 = num * ck.g2[0];

//     //e(w, g ^ (a - i))
//     libff::GT<ppT> gagi1 = ppT::reduced_pairing(num1 + ck.g1[1], witness.w2);
//     libff::GT<ppT> gagi3 = ppT::reduced_pairing(witness.w, num2 + ck.g2[1]);

//     libff::print_header("e(w, g ^ (a-i))");
//     gagi1.print();
//     gagi3.print();

//     // right2: e(g ^ eval, g)
 
//     libff::GT<ppT> gevalg = ppT::reduced_pairing(witness.eval * ck.g1[0], ck.g2[0]); //eval which side? doesnt matter.
//     libff::GT<ppT> gevalg2 = ppT::reduced_pairing(ck.g1[0], witness.eval * ck.g2[0]);

//     libff::print_header(" e(g ^ eval, g)");
//     gevalg.print();
//     gevalg2.print();

//     //RIGHT: e(w, g ^ (a-i)) * e(g ^ eval, g), +/* 다르다..?

//     libff::GT<ppT> test_one_mul = gagi1 * gevalg;
//     printf("Test_one\n");

//     test_one_mul.print();

//     libff::print_header("2. e(g ^ psi, g ^ (a-i)) * e(g, g) ^ eval");

//     // g ^ psi: G1
//     libff::G1<ppT> gpsi = libff::G1<ppT>::zero();
//     libff::G1<ppT> gpsi2 = libff::G1<ppT>::zero();

//     for(int i = 0; i < t - 1; i++) {
//         gpsi = witness.psi[i] * ck.g1[t - i - 2];
//         gpsi2 = gpsi + gpsi2;
//     }

//     // libff::print_header("psi");
//     // for(i = 0;i < t-1; i++) {
//     // witness.psi[i].print();
//     // }

//     libff::print_header(" g ^ psi");
//     gpsi2.print();

//     // g ^ psi: G2
//     libff::G2<ppT> gpsi_g2 = libff::G2<ppT>::zero();
//     libff::G2<ppT> gpsi2_g2 = libff::G2<ppT>::zero();

//     for(int i = 2; i < t + 1; i++) {
//         gpsi_g2 = witness.psi[t - i] * ck.g2[i - 2];
//         gpsi2_g2 = gpsi_g2 + gpsi2_g2;
//     }

//     gpsi2_g2.print();

//     libff::print_header(" g ^ psi should be same to witness");
//     witness.w.print();
//     witness.w2.print();

//     //g ^ (a - i)
//     libff::Fr<ppT> bnum = zero - witness.point;
//     libff::print_header(" (-i) ");
//     bnum.print();

//     libff::G1<ppT> bnum1 = bnum * ck.g1[0];
//     libff::G2<ppT> bnum2 = bnum * ck.g2[0];

//     // e(g ^ psi, g ^ (a - i))
//     libff::GT<ppT> gpsigagi = ppT::reduced_pairing(bnum1 + ck.g1[0], gpsi2_g2);
//     libff::GT<ppT> gpsigagi2 = ppT::reduced_pairing(gpsi2, bnum2 + ck.g2[1]);

//     libff::print_header(" g ^ (-i)");
//     bnum2.print();
//     libff::print_header(" g ^ (a - i)");
//     gpsigagi2.print();

//     //e(g, g) ^ eval

//     libff::GT<ppT> ggeval = ppT::reduced_pairing(witness.eval * ck.g1[0], ck.g2[0]);
//     libff::print_header(" e(g, g) ^ eval");
//     ggeval.print();

//     libff::GT<ppT> test_two_mul = gpsigagi2 * ggeval;
//     printf("Test_two\n");
//     test_two_mul.print();

//     if(test_one_mul == test_two_mul) {
//         libff::print_header("Test 2: 1 = 2 is the Same. Pass");
//     } else {
//         libff::print_header("Reject.");
//     }

//     libff::print_header("3. e(g, g) ^ psi(a)(a - i) + eval");

//     libff::Fr<ppT> don3 = ck.a - witness.point;
//     libff::Fr<ppT> don4 = zero - witness.point;

//     libff::GT<ppT> base = ppT::reduced_pairing(gpsi2, don3 * ck.g2[0]);

//     libff::print_header(" g ^ (-i)");
//     (don3 * ck.g2[0]).print();

//     libff::print_header(" g ^ (a - i)");
//     ((don4 * ck.g2[0]) + ck.g2[1]).print();

//     libff::print_header(" g ^ (a - i)");
//     base.print();

//     libff::GT<ppT> base2 = ppT::reduced_pairing(witness.eval * ck.g1[0], ck.g2[0]);

//     libff::print_header("(g, g) ^ eval");
//     base2.print();

//     libff::GT<ppT> test_three = base * base2;
//     printf("Test_three\n");
//     test_three.print();

//     if(test_three == test_two_mul) {
//         libff::print_header("Test 3: 3 = 2 is the Same. Pass");
//     } else {
//         libff::print_header("Reject.");
//     }

//     libff::print_header("4. e(g, g) ^ poly(a)");

//     libff::G1<ppT> emp = libff::G1<ppT>::zero();
//     libff::G1<ppT> commitit = libff::G1<ppT>::zero();

//     for(size_t i = 1; i < t + 1; i++) {
//         if(poly[t - i] == 0) {
//             continue;
//         }
//         else {
//             emp = poly[t - i] * ck.g1[i - 1];
//             commitit = emp + commitit;
//         }
//     }

//     libff::print_header(" g ^ poly(a): G1");
//     commitit.print();

//     libff::G2<ppT> emp2 = libff::G2<ppT>::zero();
//     libff::G2<ppT> commitit2 = libff::G2<ppT>::zero();

//     for(size_t i = 1; i < t + 1; i++) {
//         if(poly[t - i] == 0) {
//             continue;
//         }
//         else {
//             emp2 = poly[t - i] * ck.g2[i - 1];
//             commitit2 = emp2 + commitit2;
//         }
//     }

//     libff::print_header(" g ^ poly(a): G2");
//     commitit2.print();

//     libff::GT<ppT> test_four = ppT::reduced_pairing(commitit, ck.g2[0]);  
//     libff::GT<ppT> test_four_g2 = ppT::reduced_pairing(ck.g1[0], commitit2);

//     printf("Test_four\n");
//     test_four.print();
//     test_four_g2.print();

//     if(test_four == test_three || test_four_g2 == test_three) {
//         libff::print_header("Test 4: 4 = 3 is the Same. Pass");
//     } else {
//         libff::print_header("Reject.");
//     }


//     libff::print_header("5. e(C, g)");

//     libff::GT<ppT> test_five = ppT::reduced_pairing(commit.g1, ck.g2[0]);
//     printf("Test_five\n");
//     test_five.print();
//     libff::GT<ppT> test_five_g2 = ppT::reduced_pairing(ck.g1[0], commit.g2);
//     test_five_g2.print();

//     if(test_five == test_four || test_five_g2 == test_four_g2) {
//         libff::print_header("Test 5: 5 = 4 is the Same. Pass");
//     } else {
//         libff::print_header("Reject.");
//     }

//     return true;
// }

} //libsnark
#endif // KZG_TCC_