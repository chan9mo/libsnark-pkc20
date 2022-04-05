/*
run 파일을 따로 만드는 것은, 실행 부분을 따로 빼놓음으로서 편의성을 제공하기 위함이다. 필수적이지는 않으나 타 스킴들이 모두
run 파일을 따로 두기 때문에 참고하기 바람. (Changmo Yang)
*/



/** @file
 *****************************************************************************

 Implementation of functionality that runs the SNARK for Bivariate Polynomial Evalution.
 See bpe.hpp .

 *****************************************************************************/

#ifndef RUN_BPE_TCC_
#define RUN_BPE_TCC_

#include <sstream>
#include <type_traits>

#include <libsnark/libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/dario/components/evalproof/bpe.hpp>
#include <libsnark/zk_proof_systems/dario/components/polycommit/bpc.hpp>

namespace libsnark {
/**
 * The code below provides an example of all stages of running BPC.
 */
template<typename ppT>
bool run_bpe(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization)
{
    libff::enter_block("Call to run_bpe");
    //r1cs_gg_ppzksnark_getGenerator<ppT> G;
    libff::print_header("CRS Generator");
    bpc_key<ppT> crs = bpc_key<ppT>(example.dimension, example.length);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of CRS");
        crs = libff::reserialize<bpc_key<ppT> >(crs);
        libff::leave_block("Test serialization of CRS");
    }

    bpc_poly<ppT> poly_p = bpc_poly<ppT>((2, 3, 2), (3, 0, 1), (0, 0, 4));
    bpc_poly<ppT> poly_q = bpc_poly<ppT> ();
    //P : 
    //Q : 

    libff::print_header("BPE Prover");
    bpe_proof<ppT> proof = bpe_prover<ppT>(crs.ck, bpe_statement.u, bpe_witness.w);
    printf("\n"); libff::print_indent(); libff::print_mem("after BPE Prover");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of proof");
        proof = libff::reserialize<bpe_proof<ppT> >(proof);
        libff::leave_block("Test serialization of proof");
    }

    libff::print_header("BPE Verifier");
    bool ans = bpe_verifier<ppT>(crs.ck, bpe_statement.u, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after BPE Verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
   

    libff::leave_block("Call to run_bpe");

    return ans;
}

} // libsnark

#endif // RUN_BPE_TCC_

/* 고칠점
1. Poly, u, w는 어떻게 입력하는 것일까?
2. BPC처럼 간단한 다항식을 대입해도 되는 것일까?