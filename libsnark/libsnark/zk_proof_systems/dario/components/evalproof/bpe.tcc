/** @file
*****************************************************************************
Implementation of Polynomial Commitment at QPP-Model
See bpc.hpp.
*****************************************************************************/

#ifndef BPE_TCC_
#define BPE_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>
#include <libsnark/zk_proof_systems/dario/components/polycommit/bpc.hpp>
#include <libsnark/zk_proof_systems/dario/components/polycommit/bpc.tcc>

namespace libsnark {

template<typename ppT> bpc_key<ppT> bpe_generator (int &dimension, int &length) {
    libff::enter_block("BPE_generator : BPC");

   //random element: g1, h, g2, alpha(a), beta(s), gamma(t)
    const libff::Fr<ppT> alpha = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> beta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> gamma = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> delta = libff::Fr<ppT>::random_element();
    const libff::G1<ppT> g1 = libff::G1<ppT>::random_element();
    const libff::G1<ppT> h = libff::G1<ppT>::random_element();
    const libff::G2<ppT> g2 = libff::G2<ppT>::random_element();

    //calculated element: g1hat, g2hat, hhat, h_s, g2_s
    libff::G1<ppT> g1_hat = alpha * g1;
    libff::G2<ppT> g2_hat = alpha * g1;
    libff::G1<ppT> h_hat = alpha * h;
    libff::G1<ppT> h_s = beta * h;
    libff::G2<ppT> g2_s = beta * g2;

    //vector element: g1_ij, g1_hat_ij
    
    libff::G1_vector<ppT> g1_ij = libff::G1_vector<ppT>::one();
    libff::G1_vector<ppT> g1_hat_ij = libff::G1_vector<ppT>::one();

    for (int i=0; i<dimension; i++) {
        for (int j=0; j<length; j++) {
            g1_ij[i][j] = g1 * (beta * i) * (delta * j) ;
            g1_hat_ij[i][j] = g1_hat * (beta * i) * (delta * j);
        }
    }

    bpc_key<ppT> ck = bpc_key<ppT>(
                            std::move(dimension),
                            std::move(length),
                            std::move(g2),
                            std::move(h),
                            std::move(g2_hat),
                            std::move(h_hat),
                            std::move(g1_ij),
                            std::move(g1_hat_ij));
    return ck;
}

template <typename ppT> bpe_proof<ppT> bpe_prover(bpc_key<ppT> &ck, bpe_statement<ppT> &u, bpe_witness<ppT> &w){
    libff::enter_block("BPE_Prover");

    //W 계산 ?: BPC Poly 사용
    bpc_poly<ppT> poly = libff::Fr<ppT>::random_element();
    libff::G1<ppT> c = libff::G1<ppT>::one();
    libff::G1<ppT> c_hat = libff::G1<ppT>::one(); 

    //W 커밋, randomness: omega 추가
    bpc_commit<ppT> delta = bpc_commit<ppT>(ck, poly);
    libff::Fr<ppT> random_omega = libff::Fr<ppT>::random_element();

    //g_tilde, x, y, beta(U) 계산
    libff::Fr<ppT> x = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> y = libff::Fr<ppT>::random_element();

    libff::G1<ppT> g_tilde = ck.h_s - (ck.h * u.point);
    libff::GT<ppT> beta = ppT::reduced_pairing((ck.h * x) + (g_tilde * y), ck.g2);

    //beta를 hash (?)
    libff::Fr<ppT> hash_e = std::hash<ppT>(u, delta, beta);

    //sigma, tau 계산
    libff::Fr<ppT> Zq = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> sigma = ppT::modular((x - (w.rho_prime - w.rho) * hash_e), Zq); //(x - (w.rho_prime - w.rho) * e) modular q
    libff::Fr<ppT> tau = ppT::modular((y - random_omega * hash_e), Zq);//(y - random_omega * e) modular q

    bpe_proof<ppT> proof = bpe_proof<ppT>(std::move(delta), std::move(hash_e), std::move(sigma), std::move(tau));
    return proof;

}

template <typename ppT> bool bpe_verifier(bpc_key<ppT> &ck, bpe_statement<ppT> &u, bpe_proof<ppT> &proof){

bool b1 = bpc_commit_verifier(&ck, u.commit);
bool b2 = bpc_commit_verifier(&ck, u.commit_prime);
bool b3 = bpc_commit_verifier(&ck, proof.commit);

const libff::G1<ppT> alpha = ppT::reduced_pairing(proof.commit.c, (ck.g2_s - (ck.g2 * u.point))) * (ppT::reduced_pairing(u.commit.c - u.commit_hat.c, ck.g2)).inverse();
const libff::G1<ppT> beta = ppT::reduced_pairing(ck.h * proof.sigma * ((ck.h_s - (ck.h * u.point)) * proof.tau), ck.g2) + (alpha * proof.hash);

bool b4 = proof.hash == (hash(&u, proof.commit, beta));
bool result = b1 & b2 & b3 & b4 ;

return result;
}

#endif


