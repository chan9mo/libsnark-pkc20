/*
run 파일을 따로 만드는 것은, 실행 부분을 따로 빼놓음으로서 편의성을 제공하기 위함이다. 필수적이지는 않으나 타 스킴들이 모두
run 파일을 따로 두기 때문에 참고하기 바람. (Changmo Yang)
*/



/** @file
 *****************************************************************************

 Implementation of functionality that runs the Bivariate Polynomial Commitment for
 a given Polynomial.

 See bpc.hpp .

 *****************************************************************************/

#ifndef RUN_BPC_TCC_
#define RUN_BPC_TCC_

#include <sstream>
#include <type_traits>

#include <libsnark/libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/dario/components/polycommit/bpc.hpp>

namespace libsnark {
/**
 * The code below provides an example of all stages of running BPC.
 */
template<typename ppT>
bool run_bpc(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization)
{
    libff::enter_block("Call to run_bpc");
    //r1cs_gg_ppzksnark_getGenerator<ppT> G;
    libff::print_header("Commit-Key Generator");
    bpc_key<ppT> keypair = bpc_key<ppT>(example.dimension, example.length);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of keys");
        commitkey = libff::reserialize<bpc_key<ppT> >(commitkey);
        libff::leave_block("Test serialization of keys");
    }

//Poly 받을 부분 작성 요망.

    bpc_poly<ppT> poly = bpc_poly<ppT>((2, 3, 2), (3, 0, 1), (0, 0, 4));
    //Poly : 2 + 3x + 2x^2 + 3y + yx^2 + 4y^2x^2

    libff::print_header("BPC Commit");
    bpc_commit<ppT> commit = bpc_commit<ppT>(keypair.ck, poly);
    printf("\n"); libff::print_indent(); libff::print_mem("after commit");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of commit");
        commit = libff::reserialize<bpc_commit<ppT> >(commit);
        libff::leave_block("Test serialization of commit");
    }

    libff::print_header("BPC Commit Verifier");
    bool ans = bpc_commit_verifier<ppT>(keypair.ck, commit.commit, poly);
    printf("\n"); libff::print_indent(); libff::print_mem("after commit verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
   

    libff::print_header("BPC Open Verifier");
    bool ans2 = bpc_open_verifier<ppT>(keypair.ck, commit.commit, poly);
    printf("\n"); libff::print_indent(); libff::print_mem("after open verifier");
    printf("* The verification result is: %s\n", (ans2 ? "PASS" : "FAIL"));

    libff::leave_block("Call to run_bpc");

    return ans2;
}

} // libsnark

#endif // RUN_BPC_TCC_
