/** @file
*****************************************************************************
Implementation of Polynomial Commitment at QPP-Model
See bpc.hpp.
*****************************************************************************/

#ifndef BPC_TCC_
#define BPC_TCC_

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

namespace libsnark {

//Key I/O

template<typename ppT>
bool bpc_key<ppT>::operator==(const bpc_key<ppT> &other) const
{
    return (this->dimension == other.dimension &&
            this->length == other.length &&
            this->g2 == other.g2 &&
            this->h == other.h &&
            this->g2_hat == other.g2_hat &&
            this->h_hat == other.h_hat &&
            this->g1_ij == other.g1_ij &&
            this->g1_hat_ij == other.g1_hat_ij);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const bpc_key<ppT> &ck)
{
    out << ck.dimension << OUTPUT_NEWLINE;
    out << ck.length << OUTPUT_NEWLINE;
    out << ck.g2 << OUTPUT_NEWLINE;
    out << ck.h << OUTPUT_NEWLINE;
    out << ck.g2_hat << OUTPUT_NEWLINE;
    out << ck.h_hat << OUTPUT_NEWLINE;
    out << ck.g1_ij << OUTPUT_NEWLINE;
    out << ck.g1_hat_ij << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, bpc_key<ppT> &ck)
{
    in >> ck.dimension;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ck.length;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ck.g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ck.h;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ck.g2_hat;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ck.h_hat;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ck.g1_ij;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ck.g1_hat_ij;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

//Commit I/O

template<typename ppT>
bool bpc_commit<ppT>::operator==(const bpc_commit<ppT> &other) const
{
    return (this->commit == other.commit &&
            this->commit_hat == other.commit_hat &&
            this->rho == other.rho);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const bpc_commit<ppT> &ck)
{
    out << ck.commit << OUTPUT_NEWLINE;
    out << ck.commit_hat << OUTPUT_NEWLINE;
    out << ck.rho << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, bpc_commit<ppT> &ck)
{
    in >> ck.commit;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ck.commit_hat;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ck.rho;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT> bpc_key<ppT> bpc_generator (int &dimension, int &length) {
    libff::enter_block("BPC_generator");

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

// template <typename ppT> bpc_poly<ppT> mpc_to_bpc(bpc_unipoly<ppT> &poly){
    
//     libff::G1_2dvector<ppT> multipoly;
//     libff::G1_vector<ppT> uni_multipoly;

//     if (poly.count == 0) {
//         poly.count++;
//     }
//     else poly.count++;

//     for(int i=0;i<sizeof(poly.coef);i++) {
//         multipoly[i][poly.count] = poly.coef[i];
//     }  
//     return multipoly;
// }

template <typename ppT> bpc_commit<ppT> bpc_commitment(bpc_key<ppT> &ck, libff::G1_2dvector<ppT> &poly){
    libff::enter_block("BPC_commit");

    //rho, c, c_hat 설정
    const libff::Fr<ppT> rho = libff::Fr<ppT>::random_element();
    libff::G1<ppT> c = libff::G1<ppT>::one();
    libff::G1<ppT> c_hat = libff::G1<ppT>::one(); 

    //∏g^a 계산
    for (int i=0; i<ck.dimension; i++) {
        for (int j=0; j<ck.length; j++) {
            c += ck.g1_ij[i][j] * poly.coef[i][j];
            c_hat += ck.g1_hat_ij[i][j] * poly.coef[i][j];
        }
    }

    //h^rho 곱하기
    c += ck.h * rho;
    c_hat += ck.h_hat * rho;

    bpc_commit<ppT> commit = bpc_commit<ppT>(std::move(c), std::move(c_hat), std::move(rho));
    return commit;

}

template <typename ppT> bool bpc_commit_verifier(bpc_key<ppT> &ck, bpc_commit<ppT> &commit){
    libff::GT<ppT> g_is_hat = ppT::reduced_pairing(commit.c, ck.g_hat);
    libff::GT<ppT> c_is_hat = ppT::reduced_pairing(commit.c_hat, ck.g);
    
    bool result = (g_is_hat == c_is_hat);
    return result;
}

template <typename ppT> bool bpc_open_verifier(bpc_key<ppT> &ck, bpc_commit<ppT> &commit, libff::G1_2dvector<ppT> &poly) {

bool b1 = bpc_commit_verifier(&ck, &commit);

const libff::G1<ppT> c = libff::G1<ppT>::one();
for (int i=0; i<ck.dimension; i++) {
        for (int j=0; j<ck.length; j++) {
            c += ck.g1_ij[i][j] * poly.coef[i][j];
        }
    }
bool b2 = commit.c == (ck.h * commit.rho);
bool result = b1 & b2;

return result;
}
}

#endif
