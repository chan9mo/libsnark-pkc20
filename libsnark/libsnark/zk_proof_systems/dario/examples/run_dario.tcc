/*
run 파일을 따로 만드는 것은, 실행 부분을 따로 빼놓음으로서 편의성을 제공하기 위함이다. 필수적이지는 않으나 타 스킴들이 모두
run 파일을 따로 두기 때문에 참고하기 바람. (Changmo Yang)
*/

/** @file
 ********************************************************************x*********

 Implementation of functionality that runs the RQ-SNARK.
 See dario.hpp.

 *****************************************************************************/

#ifndef RUN_DARIO_TCC_
#define RUN_DARIO_TCC_

#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>
//#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/dario/components/evalproof/bpe.hpp>
#include <libsnark/zk_proof_systems/dario/components/polycommit/bpc.hpp>
#include <libsnark/zk_proof_systems/dario/dario.hpp>
#include <libsnark/zk_proof_systems/dario/components/lego/lego_cp_snark.hpp>
#include <libsnark/zk_proof_systems/dario/components/lego/lego_ss.hpp>
#include <libsnark/zk_proof_systems/dario/dario_params.hpp>

namespace libsnark {
/**
 * The code below provides an example of all stages of running Dario.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the crs_generator for BPC, and LegoSNARK on input a given
 *     constraint system CS to create a proving, and dimension/length integer.
 * (2) The "prover", which runs the dario_prover on input the CRS, 
       a statement, and a witness).
 * (3) The "verifier", which runs the dario_verifier on input the CRS,
 *     a statement , and a proof.
 */
template<typename ppT>
bool run_dario(r1cs_example<libff::Fr<ppT>> &example,
               bool test_serialization)
{
    libff::enter_block("Call to run_dario");
    //r1cs_gg_ppzksnark_getGenerator<ppT> G;
    libff::print_header("CRS Generator");
    
    int dimension = 3;
    int length = 100;

    libff::Fr_vector<ppT> random_commit;
    for (int i = 0; i < length; ++i)
    {
        random_commit.emplace_back(libff::G1<ppT>::random_element());
    }
    libff::G1<ppT> random_commit_prime = libff::G1<ppT>::one();
    statement<ppT> random_statement = statement<ppT>(std::move(random_commit), std::move(random_commit_prime));

    libff::Fr_vector<ppT> random_openings;
    for (int i = 0; i < length; ++i)
    {
        random_openings.emplace_back(libff::Fr<ppT>::random_element());
    }
    libff::Fr<ppT> random_openings_prime = libff::Fr<ppT>::one();
    witness<ppT> random_witness = witness<ppT>(std::move(random_openings), std::move(random_openings_prime));
    relation<ppT> random_relation = relation<ppT>(std::move(random_statement), std::move(random_witness));

    dario_crs<ppT> crs = crs_generator<ppT>(dimension, length, example.constraint_system, example.primary_input, random_relation);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of CRS");
        crs.crs_bpc = libff::reserialize<bpc_key<ppT>>(crs.crs_bpc);
        crs.crs_lego = libff::reserialize<lego_cp_snark_keypair<ppT>>(crs.crs_lego);
        libff::leave_block("Test serialization of CRS");
    }

    libff::print_header("Dario Prover");
    
    //Statement
    libff::Fr_2dvector<ppT> public_poly;
    libff::Fr_vector<ppT> uni_public_poly;
    libff::Fr_2dvector<ppT> commit_poly;
    libff::Fr_vector<ppT> uni_commit_poly;

    for (int i=0; i<3; i++) {
        for (int j=0; j<3; j++) {
            uni_public_poly.emplace_back(libff::G1<ppT>::random_element());
            uni_commit_poly.emplace_back(libff::G1<ppT>::random_element());
        }
        public_poly.emplace_back(uni_public_poly);
        commit_poly.emplace_back(uni_commit_poly);
        uni_public_poly.clear();
        uni_commit_poly.clear();
    }

    bpc_commit<ppT> commit = bpc_commitment<ppT>(crs.crs_bpc, commit_poly);
    
    dario_statement<ppT> d_statement = dario_statement<ppT>(std::move(commit), 
                                                       std::move(public_poly));
    //Witness
    libff::Fr_2dvector<ppT> Tpoly;
    libff::Fr_vector<ppT> uni_Tpoly;

    for (int i=0; i<3; i++) {
        for (int j=0; j<3; j++) {
            uni_Tpoly.emplace_back(libff::G1<ppT>::random_element());
        }
        Tpoly.emplace_back(uni_Tpoly);
        uni_Tpoly.clear();
    }

    dario_witness<ppT> d_witness = dario_witness<ppT>(std::move(commit_poly),
                                                 std::move(Tpoly));

    // if (test_serialization)
    // {
    //     libff::enter_block("Test serialization of Input");
    //     d_statement = libff::reserialize<dario_statement<ppT>>(d_statement);
    //     d_witness = libff::reserialize<dario_witness<ppT>>(d_witness);
    //     libff::leave_block("Test serialization of Input");
    // }

    //Prover
    ;
    printf("\n"); libff::print_indent(); libff::print_mem("after Dario Prover");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of proof");
        d_proof = libff::reserialize<dario_proof<ppT>>(d_proof);
        libff::leave_block("Test serialization of proof");
    }dario_proof<ppT> d_proof = dario_prover<ppT>(crs, d_statement, d_witness, example.primary_input)

    //Verifier

    libff::print_header("Dario Verifier");
    bool ans = dario_verifier<ppT>(crs, d_statement, d_proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after Dario Verifier");
    printf("* The verification result is: %s\n", (ans ? "ACCEPT" : "REJECT"));
   
    //test_affine_verifier<ppT>(keypair.vk, example.primary_input, proof, ans);  

    libff::leave_block("Call to run_dario");

    return ans;
}

} // libsnark

#endif