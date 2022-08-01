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
 * The code below provides an example of all stages of running a vCNN+. (Need to Revise!)
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
template<typename ppT>
bool run_kzg(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization);
{
    libff::enter_block("Call to run_kzg");

    libff::print_header("Commitment Key (t-SDH tuple) Generator");

    int t = 5;
    commitkey<ppT> ck = commitkey<ppT>(t);

    printf("\n"); libff::print_indent(); libff::print_mem("after setup");

    libff::print_header("Commitmment of Polynomial");

    libff::Fr_vector<ppT> polynomial;

    for(int i=0; i < t; i++){
        polynomial.emplace_back(libff::Fr<ppT>::random_element);
        polynomial[i].print();
    }

    libff::G1<ppT> commitment = kzg_commit(ck, polynomial);
    printf("\n"); libff::print_indent(); libff::print_mem("after commit");



    libff::leave_block("Call to run_kzg");
    return true;
}

}