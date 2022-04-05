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

template <typename ppT> bpc_poly<ppT> mpc_to_bpc(bpc_unipoly<ppT> &poly){
    
    libff::G1_vector<libff::G1_vector<ppT>> multipoly = libff::G1_vector<libff::G1_vector<ppT>>::one();

    if (poly.count == 0) {
        poly.count++;
    }
    else poly.count++;

    for(int i=0;i<sizeof(poly.coef);i++) {
        multipoly[i][poly.count] = poly.coef[i];
    }  
    return multipoly;
}

template <typename ppT> bpc_commit<ppT> bpc_commitment(bpc_key<ppT> &ck, bpc_poly<ppT> &poly){
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
    
    bool result = g_is_hat == c_is_hat;
    return result;
}

template <typename ppT> bool bpc_open_verifier(bpc_key<ppT> &ck, bpc_commit<ppT> &commit, bpc_poly<ppT> &poly) {

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

#endif
