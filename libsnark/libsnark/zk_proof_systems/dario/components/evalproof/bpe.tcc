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
#include <string>

#include <openssl/sha.h>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>
#include <libsnark/zk_proof_systems/dario/components/polycommit/bpc.hpp>
#include <libsnark/zk_proof_systems/dario/components/polycommit/bpc.tcc>

namespace libsnark {

template<typename ppT>
bool bpe_statement<ppT>::operator==(const bpe_statement<ppT> &other) const
{
    return (this->commit == other.commit &&
            this->commit_hat == other.commit_hat &&
            this->point == other.point);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const bpe_statement<ppT> &st)
{
    out << st.commit << OUTPUT_NEWLINE;
    out << st.commit_prime << OUTPUT_NEWLINE;
    out << st.point << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, bpe_statement<ppT> &st)
{
    in >> st.commit;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> st.commit_prime;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> st.point;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool bpe_witness<ppT>::operator==(const bpe_witness<ppT> &other) const
{
    return (this->Ppoly == other.Ppoly &&
            this->Qpoly == other.Qpoly &&
            this->rho == other.rho &&
            this->rho_prime == other.rho_prime);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const bpe_witness<ppT> &wit)
{
    out << wit.Ppoly << OUTPUT_NEWLINE;
    out << wit.Qpoly << OUTPUT_NEWLINE;
    out << wit.rho << OUTPUT_NEWLINE;
    out << wit.rho_prime << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, bpe_witness<ppT> &wit)
{
    in >> wit.Ppoly;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> wit.Qpoly;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> wit.rho;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> wit.rho_prime;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool bpe_proof<ppT>::operator==(const bpe_proof<ppT> &other) const
{
    return (this->commit == other.commit &&
            this->hash == other.hash &&
            this->sigma == other.sigma &&
            this->tau == other.tau);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const bpe_proof<ppT> &proof)
{
    out << proof.commit << OUTPUT_NEWLINE;
    out << proof.hash << OUTPUT_NEWLINE;
    out << proof.sigma << OUTPUT_NEWLINE;
    out << proof.tau << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, bpe_proof<ppT> &proof)
{
    in >> proof.commit;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.hash;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.sigma;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.tau;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT> bpc_key<ppT> bpe_generator (int &dimension, int &length) {
    libff::enter_block("Call to BPE-generator : BPC");

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
    libff::G2<ppT> g2_hat = alpha * g2;
    libff::G1<ppT> h_hat = alpha * h;
    libff::G1<ppT> h_s = beta * h;
    libff::G2<ppT> g2_s = beta * g2;

    //vector element: g1_ij, g1_hat_ij
    
    libff::G1_2dvector<ppT> g1_ij;
    libff::G1_vector<ppT> uni_g1_ij;
    libff::G1_2dvector<ppT> g1_hat_ij;
    libff::G1_vector<ppT> uni_g1_hat_ij;

    for (int i=0; i<dimension; i++) {
        for (int j=0; j<length; j++) {
            uni_g1_ij.emplace_back(g1 * (beta * i) * (delta * j)) ;
            uni_g1_hat_ij.emplace_back(g1_hat * (beta * i) * (delta * j));
        }
        g1_ij.emplace_back(uni_g1_ij);
        g1_hat_ij.emplace_back(uni_g1_hat_ij);
        uni_g1_ij.clear();
        uni_g1_hat_ij.clear();
    }

    libff::leave_block("Call to BPE-generator : BPC");

    bpc_key<ppT> ck = bpc_key<ppT>(
                            std::move(dimension),
                            std::move(length),
                            std::move(g2),
                            std::move(g2_s),
                            std::move(h),
                            std::move(g2_hat),
                            std::move(h_hat),
                            std::move(g1_ij),
                            std::move(g1_hat_ij));
    return ck;
}

template <typename ppT> bpe_proof<ppT> bpe_prover(bpc_key<ppT> &ck, bpe_statement<ppT> &u, bpe_witness<ppT> &w){
    libff::enter_block("Call to BPE-Prover");

    //W 계산 ?: BPC Poly 사용
    libff::Fr_2dvector<ppT> Wpoly;
    libff::Fr_vector<ppT> uni_Wpoly;

    libff::Fr_2dvector<ppT> coeff;
    libff::Fr_vector<ppT> uni_coeff;
    for (int i=0; i<3; i++) {
        for (int j=0; j<3; j++) {
                // coeff[i][j] = w.Ppoly[i][j] - w.Qpoly[i][j];
                uni_coeff.emplace_back(w.Ppoly[i][j] - w.Qpoly[i][j]);
        }
        coeff.emplace_back(uni_coeff);
        uni_coeff.clear();
    }

    libff::Fr_2dvector<ppT> divisor;
    libff::Fr_vector<ppT> uni_divisor;
    uni_divisor.emplace_back(u.point);
    uni_divisor.emplace_back(libff::Fr<ppT>::one());
    divisor.emplace_back(uni_divisor);

    // Wpoly = factorize<ppT>(coeff, divisor);  
    // Problem: You need to make function 'factorize'

    for (int i=0; i<3; i++) {
        for (int j=0; j<3; j++) {
            uni_Wpoly.emplace_back(libff::Fr<ppT>::random_element());
        }
        Wpoly.emplace_back(uni_Wpoly);
        uni_Wpoly.clear();
    }

    libff::G1<ppT> c = libff::G1<ppT>::one();
    libff::G1<ppT> c_hat = libff::G1<ppT>::one(); 

    //W 커밋, randomness: omega 추가
    bpc_commit<ppT> delta = bpc_commitment(ck, Wpoly);
    libff::Fr<ppT> random_omega = libff::Fr<ppT>::random_element();


    //g_tilde, x, y, beta(U) 계산
    libff::Fr<ppT> x = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> y = libff::Fr<ppT>::random_element();

    libff::G1<ppT> g_tilde = ck.h_s - (u.point * ck.h);
    libff::GT<ppT> beta = ppT::reduced_pairing((x * ck.h) + (y * g_tilde), ck.g2);

    int hash_e = (sha256<ppT>(as_string<ppT>(u.commit) + as_string<ppT>(u.commit_prime) + to_string(u.point.as_ulong()) + as_string<ppT>(delta) + as_string<ppT>(beta)));

    libff::Fr<ppT> sigma = x - (w.rho_prime - w.rho);
    libff::Fr<ppT> tau = y - random_omega;
    for(int m=0;m<hash_e;m++) {
        sigma = sigma + x - (w.rho_prime - w.rho);
        tau = tau + y - random_omega;
    }
    // libff::Fr<ppT> sigma = x - (w.rho_prime - w.rho) * hash_e; //(x - (w.rho_prime - w.rho) * e) modular q
    // libff::Fr<ppT> tau = y - random_omega * hash_e;//(y - random_omega * e) modular q

    libff::leave_block("Call to BPE-Prover");

    bpe_proof<ppT> proof = bpe_proof<ppT>(std::move(delta), std::move(hash_e), std::move(sigma), std::move(tau));
    return proof;
}

template <typename ppT> bool bpe_verifier(bpc_key<ppT> &ck, bpe_statement<ppT> &u, bpe_proof<ppT> &proof){

    libff::enter_block("Call to BPE_Verifier");

    bool b1 = bpc_commit_verifier(ck, u.commit);
    bool b2 = bpc_commit_verifier(ck, u.commit_prime);
    bool b3 = bpc_commit_verifier(ck, proof.commit);

    libff::G1<ppT> g_tilde = ck.h_s - (u.point * ck.h);

    libff::GT<ppT> alpha = ppT::reduced_pairing(proof.commit.commit, (ck.g2_s - (u.point * ck.g2))) + (ppT::reduced_pairing(u.commit.commit - u.commit_prime.commit, ck.g2)).unitary_inverse();
    libff::GT<ppT> beta = ppT::reduced_pairing(((proof.sigma * ck.h) + (proof.tau * g_tilde)), ck.g2) + (alpha ^ (libff::Fr<ppT>)proof.hash);

    bool b4 = (proof.hash == (sha256<ppT>(as_string<ppT>(u.commit) + as_string<ppT>(u.commit_prime) + to_string(u.point.as_ulong()) + as_string<ppT>(proof.commit) + as_string<ppT>(beta))));
    bool result = b1 & b2 & b3 & b4 ;

    libff::leave_block("Call to BPE_Verifier");

return result;
}
}
#endif


