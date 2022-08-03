/** @file
 *****************************************************************************

 Implementation of interfaces for Kate Commitment for R1CS example.

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RUN_KZG_TCC_
#define RUN_KZG_TCC_

#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/kzg/kzg.hpp>

namespace libsnark {

/**
 * The code below provides an example of all stages of running a Kate Commitment.
 *
 * This is the version we use for the DEMO CHECK
 */
template<typename ppT>
bool run_kzg(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization)
{
    libff::enter_block("Call to run_kzg");

    int t = 28374;

    /* Generate Polynomial to Commit: we need to put Convolution Poly. in this section */

    libff::Fr_vector<ppT> poly(t);

    for(int i = 0; i < t; i++) {
        libff::Fr<ppT> random = libff::Fr<ppT>::random_element();
        poly[i] = random;
        // poly[i].print();
    }

    /* Generate Random Point for Evaluation */

    libff::Fr<ppT> point = libff::Fr<ppT>::random_element();
    // libff::Fr<ppT> point = convert<ppT>(1);
    // point.print();

    /* Generate t-SDH tuple, and select secret randomness t */

    libff::print_header("Generate Key: t-SDH Tuple");
    commitkey<ppT> ck = kzg_setup<ppT>(t);
    printf("\n"); libff::print_indent(); libff::print_mem("after setup");

    /* Commit Polynomial into Product: G1-element */

    libff::print_header("Commit Polynomial");
    commitment<ppT> commit = kzg_commit<ppT>(ck, poly, t);
    printf("\n"); libff::print_indent(); libff::print_mem("after commit");

    /* Generate witness of the evaluation + Evaluate the Polynomial */

    libff::print_header("Create Witness");
    witness<ppT> wit = kzg_witness<ppT>(ck, poly, point, t);
    printf("\n"); libff::print_indent(); libff::print_mem("after create-witness");

    /* Verify evaluation */
    libff::print_header("Verify Evaluation of Polynomial");
    bool verifyresult = kzg_vfyeval<ppT>(ck, commit, wit);
    printf("\n"); libff::print_indent(); libff::print_mem("after vfyeval");

    /* Verify evaluation TEST-DEMO*/
    // libff::print_header("Verify TEST-Logical Error");
    // bool testresult = kzg_testvfy<ppT>(ck, commit, wit, poly2, t);
    // printf("\n"); libff::print_indent(); libff::print_mem("after testvfy");

    libff::leave_block("Call to run_kzg");
    return verifyresult;

    //clear all
    poly.clear();
    point.clear();
}

// /**
//  * The code below provides an example of all stages of running a Kate Commitment.
//  *
//  * Of course, in a real-life scenario, we would have three distinct entities,
//  * mangled into one in the demonstration below. The three entities are as follows.
//  * (1) The "generator", which generatrs t-SDH tuple, polynomial to prove, and random evaluation point.
//  *
//  * (2) The "committer", which runs the Commitment on input the commitment key,
//  *
//  * (3) The "verifier", which runs the VfyEval on input the commitment key, commitment, and witness.
//  */
// template<typename ppT>
// bool run_kzg(const r1cs_example<libff::Fr<ppT> > &example,
//                         const bool test_serialization)
// {
//     libff::enter_block("Call to run_kzg");

//     int i;
//     int t = 17;

//     /* Generate Polynomial to Commit: we need to put Convolution Poly. in this section */

//     libff::print_header("Make Polynomial");

//     libff::Fr_vector<ppT> poly;
//     for(i = 0; i < t; i++) {
//         libff::Fr<ppT> random = libff::Fr<ppT>::random_element();
//         poly.emplace_back(random);
//         // random.print();
//     }

//     poly.emplace_back(convert<ppT>(number));

//     libff::Fr_vector<ppT> poly2;

//     for(i = 0; i < t; i++) {
//         poly2.emplace_back(poly[i]);
//     }

//     /* Generate Random Point for Evaluation */

//     libff::print_header("Generate Random point");
//     libff::Fr<ppT> point = libff::Fr<ppT>::random_element();
//     point.print();

//     /* Generate t-SDH tuple, and select secret randomness t */

//     libff::print_header("Generate Key: t-SDH Tuple");
//     commitkey<ppT> ck = kzg_setup<ppT>(t);
//     printf("\n"); libff::print_indent(); libff::print_mem("after setup");

//     /* Commit Polynomial into Product: G1-element */

//     libff::print_header("Commit Polynomial");
//     libff::G1<ppT> commit = kzg_commit<ppT>(ck, poly, t);
//     printf("\n"); libff::print_indent(); libff::print_mem("after commit");

//     /* Generate witness of the evaluation + Evaluate the Polynomial */

//     libff::print_header("Create Witness");
//     witness<ppT> wit = kzg_witness<ppT>(ck, poly, point, t);
//     printf("\n"); libff::print_indent(); libff::print_mem("after create-witness");

//     /* Verify evaluation */
//     libff::print_header("Verify Evaluation of Polynomial");
//     bool verifyevaluation = kzg_vfyeval<ppT>(ck, commit, wit);
//     printf("\n"); libff::print_indent(); libff::print_mem("after vfyeval");

//     /* Verify evaluation TEST-DEMO*/
//     libff::print_header("Verify TEST-Logical Error");
//     bool testresult = kzg_testvfy<ppT>(ck, commit, wit, poly2);
//     printf("\n"); libff::print_indent(); libff::print_mem("after testvfy");

//     libff::leave_block("Call to run_kzg");
//     return verifyevaluation;

//     //clear all
//     poly.clear();
//     point.clear();
// }

} // libsnark
#endif // RUN_KZG_TCC_