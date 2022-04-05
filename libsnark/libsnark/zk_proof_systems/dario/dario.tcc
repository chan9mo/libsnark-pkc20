/** @file
*****************************************************************************
Implementation of dario_proof of Polynomial Evaluation.
See dario.hpp.
*****************************************************************************/

#ifndef DARIO_TCC_
#define DARIO_TCC_

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
#include <libsnark/zk_proof_systems/dario/components/evalproof/bpe.hpp>
#include <libsnark/zk_proof_systems/dario/components/evalproof/bpe.tcc>

#include <libsnark/zk_proof_systems/dario/dario.hpp>
#include <libsnark/zk_proof_systems/dario/dario_params.hpp>

namespace libsnark {

/******************************** CRS Generator ********************************/

template<typename ppT>
dario_crs<ppT> crs_generator(int &dimension, 
                             int &length, 
                             r1cs_gg_ppzksnark_constraint_system<ppT> &r1cs, 
                             r1cs_gg_ppzksnark_primary_input<ppT> &primary_input, 
                             relation<ppT> &R_link) {

    libff::enter_block("Call to CRS generator");

// CRS Generator: BPC 

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

// CRS Generator: LegoSNARK

    libff::G1_vector<ppT> h_lego; // ck
    lego_ss_keypair<ppT> ss_pair; // (ek, vk) where ek:=[P] = M^T * k and vk:=([C], [a]) s.t.  C = a*k 
    libff::G1_vector<ppT> M; // Matrix M where [x]:=[M]*[w] (x is statement and w is dario_dario_dario_witness, the openings)
    r1cs_gg_ppzksnark_constraint_system<ppT> r1cs_copy(r1cs);

    // get accumulation f from gro16 keypair
    r1cs_gg_ppzksnark_keypair<ppT> gro16_keypair = r1cs_gg_ppzksnark_generator<ppT>(r1cs_copy); 
    accumulation_vector<libff::G1<ppT>> ck_prime = gro16_keypair.vk.gamma_ABC_g1; 
    
    size_t l = primary_input.size();
    h_lego.reserve(l + 1);
    M.reserve(2 * l + 4); 

    // h vector random generation
    for (size_t i = 0; i < l + 1; i++)
    {
         h_lego.emplace_back(libff::G1<ppT>::random_element());
    }

    M.emplace_back(h[0]);
    M.emplace_back(libff::G1<ppT>::zero());
    for (size_t i = 1; i < l + 1; i++)
    {
        M.emplace_back(h[i]);
    }
    M.emplace_back(libff::G1<ppT>::zero());
    M.emplace_back(ck_prime.first);
    for (size_t i = 0; i < l; i++)
    {
        M.emplace_back(ck_prime.rest[i]);
    }
    ss_pair = lego_ss_generator<ppT>(M, 2, l + 2);

    ss_pair.print();

    R_link = make_commitment<ppT>(h_lego, ck_prime, primary_input);

//KeyGen

    bpc_key<ppT> crs_bpc = bpc_key<ppT>(
                            std::move(dimension),
                            std::move(length),
                            std::move(g2),
                            std::move(h),
                            std::move(g2_hat),
                            std::move(h_hat),
                            std::move(g1_ij),
                            std::move(g1_hat_ij));
    
    lego_cp_snark_keypair<ppT> crs_lego = lego_cp_snark_keypair<ppT>(ss_pair.ek, 
                                                                     ss_pair.vk);

    dario_crs<ppT> crs = dario_crs<ppT>(std::move(crs_bpc),
                            std::move(crs_lego));

    return crs;       
}

/******************************** Polynomial Evaluation ********************************/

template<typename ppT>
libff::Fr<ppT> poly_eval(bpc_poly<ppT> &poly, 
                         libff::Fr<ppT> &point) {
    libff::Fr<ppT> eval = libff::Fr<ppT>::one();

    for(int i=0;i<sizeof(poly.coef);i++) {
        eval += poly.coef[i] * (point^i);
    }
    return eval;
}

/******************************** Prover ********************************/

template<typename ppT> 
dario_proof<ppT> prover(dario_crs<ppT> &crs, 
                        dario_statement<ppT> &st, 
                        dario_witness<ppT> &wit,
                        dario_primary_input<ppT> &primary_input) {
    
    libff::enter_block("Dario Prover");

//T를 commit하여 C_t를 얻는다.
    bpc_commit<ppT> commit_t = bpc_commit<ppT>::bpc_commitment(crs.crs_bpc, wit.Tpoly);

//C_t, statement를 hash하여 eval.point인 random를 얻는다.
    std::hash<ppT> random = std::hash<ppT>(st.commit, st.pubpoly, commit_t);
    bpc_poly<ppT> RPoly = bpc_poly<ppT>((2, 3, 2), (3, 0, 1), (0, 0, 4));

//Polynomial Evaluation 함수를 통해서 p, r, t`, p_j evaluate
    libff::Fr<ppT> p = poly_eval(st.pubpoly, random);
    libff::Fr<ppT> r = poly_eval(RPoly, random);
    libff::Fr<ppT> t_prime = poly_eval(wit.Tpoly, random);
    libff::Fr_vector<ppT> p_j = libff::Fr_vector<ppT>::random_element();
    for(int n=0;n<sizeof(wit.p_j);n++) {
        p_j[n]= poly_eval(wit.n_polys[n], random);
    }
    p_j[sizeof(wit.p_j)+1] = t_prime;

//evaluation 결과를 commit하여 C`, rho` 생성
    bpc_poly<ppT> evaluation = libff::Fr<ppT>::random_element();
    for(int k=0;k<sizeof(wit.p_j)+1;k++) {
        evaluation[k][0] = p_j[k];
    }
    
    bpc_commit<ppT> commit_prime = bpc_commit<ppT>(crs.crs_bpc, p_j);

//MUE-dario_proof 구동
    libff::GT<ppT> pair_commit = ppT::reduced_pairing(commit_t, st.commit);
    bpe_statement<ppT> statement_commit = (std::move(pair_commit), 
                                           std::move(commit_prime), 
                                           std::move(random));
    
    libff::Fr<ppT> sumpoint = st.commit.rho + commit_t.rho;
    bpe_witness<ppT> witness_commit = (std::move(p_j), 
                                       std::move(evaluation), 
                                       std::move(sumpoint), 
                                       std::move(commit_prime.rho));
    
    bpe_proof<ppT> proof_commit = bpe_prover<ppT>(std::move(crs.crs_bpc), 
                                                  std::move(statement_commit),
                                                  std::move(witness_commit));
//Lego 구동
    statement<ppT> lego_statement = statement<ppT>(std::move(commit_prime),
                                                  std::move(p),
                                                  std::move(r));

    witness<ppT> lego_witness = witness<ppT>(std::move(t_prime),
                                             std::move(p_j),
                                             std::move(commit_prime.rho));

    relation<ppT> lego_relation = relation<ppT> (std::move(lego_statement),
                                                 std::move(lego_witness));


    lego_cp_snark_proof<ppT> proof_prime = lego_cp_snark_prover<ppT>(std::move(crs.crs_lego.ek), 
                                                                     std::move(lego_relation), 
                                                                     std::move(primary_input));

//dario_proof 반환
    dario_proof<ppT> dario_proof = (std::move(commit_t), 
                              std::move(commit_prime), 
                              std::move(proof_commit), 
                              std::move(proof_prime));
}

/******************************** Verifier ********************************/
template<typename ppT>
bool verifier(dario_crs<ppT> &crs, 
              dario_statement<ppT> &st, 
              dario_proof<ppT> &dario_proof) {

//C_t, statement를 hash하여 eval.point인 random를 얻는다.
    std::hash<ppT> random =std::hash<ppT>(st.commit, st.pubpoly, dario_proof.commit_t);

//Polynomial Evaluation 함수를 통해서 p, r evaluate
    bpc_poly<ppT> RPoly = bpc_poly<ppT>((2, 3, 2), (3, 0, 1), (0, 0, 4));
    
    libff::Fr<ppT> p = poly_eval(st.pubpoly, random);
    libff::Fr<ppT> r = poly_eval(RPoly, random);

//MUE에 대한 Verify
    libff::GT<ppT> pair_commit = ppT::reduced_pairing(dario_proof.commit_t, st.commit);
    bpe_statement<ppT> statement_commit = bpe_statement<ppT>(std::move(pair_commit), 
                                                             std::move(dario_proof.commit_prime), 
                                                             std::move(random));
    bool b1 = bpe_verifier(std::move(crs.crs_bpc), 
                           std::move(statement_commit), 
                           std::move(dario_proof.proof_commit));

//Lego에 대한 Verify
    statement<ppT> lego_statement = statement<ppT>(std::move(dario_proof.commit_prime),
                                                   std::move(p),
                                                   std::move(r));

    bool b2 = lego_cp_snark_verifier(std::move(crs.crs_lego),
                                     std::move(lego_statement),
                                     std::move(dario_proof.proof_prime));

//Verify 결과 반환
    bool result = b1 & b2;
    return result;
}

#endif
}