/* Bivariate Polynomial Commit과 똑같은 스킴이지만, 
 * 여러 개의 x에 대한 단일변수 Poly를 x, y에 대한 2변수 Poly로 치환하여 연산한다.
 * {0{x0, x1, x2}, 1{x0, x1, x2}, 2{x0, x1, x2}}
 * ↓
 * {{x0y0, x1y0, x2y0}, {x0y1, x1y1, x2y1}, {x0y2, x1y2, x2y2}}
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
    libff::enter_block("Call to run_mpc");
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

    bpc_poly<ppT> poly = bpc_poly<ppT>((2, 3, 2), (3, 0, 1), (0, 4, 4));
    // Poly : {2x^2+3x+2}, {3x^2+1}, {4x+2}

    libff::print_header("MPC Commit");
    bpc_commit<ppT> commit = bpc_commit<ppT>(keypair.ck, poly);
    printf("\n"); libff::print_indent(); libff::print_mem("after commit");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of commit");
        commit = libff::reserialize<bpc_commit<ppT> >(commit);
        libff::leave_block("Test serialization of commit");
    }

    libff::print_header("MPC Commit Verifier");
    bool ans = bpc_commit_verifier<ppT>(keypair.ck, commit.commit, poly);
    printf("\n"); libff::print_indent(); libff::print_mem("after commit verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
   

    libff::print_header("MPC Open Verifier");
    bool ans2 = bpc_open_verifier<ppT>(keypair.ck, commit.commit, poly);
    printf("\n"); libff::print_indent(); libff::print_mem("after open verifier");
    printf("* The verification result is: %s\n", (ans2 ? "PASS" : "FAIL"));

    libff::leave_block("Call to run_bpc");

    return ans2;
}

} // libsnark

#endif // RUN_BPC_TCC_
