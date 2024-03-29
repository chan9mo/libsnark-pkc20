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
#include <libsnark/zk_proof_systems/dario/components/evalproof/bpe.hpp>
#include <libsnark/zk_proof_systems/dario/components/lego/lego_cp_snark.hpp>
#include <libsnark/zk_proof_systems/dario/components/lego/lego_ss.hpp>

#include <libsnark/zk_proof_systems/dario/dario.hpp>
#include <libsnark/zk_proof_systems/dario/dario_params.hpp>

namespace libsnark {

template<typename ppT>
bool dario_crs<ppT>::operator==(const dario_crs<ppT> &other) const
{
    return (this->crs_bpc == other.crs_bpc &&
            this->crs_lego == other.crs_lego);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const dario_crs<ppT> &crs)
{
    out << crs.crs_bpc << OUTPUT_NEWLINE;
    out << crs.crs_lego << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, dario_crs<ppT> &crs)
{
    in >> crs.crs_bpc;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> crs.crs_lego;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool dario_statement<ppT>::operator==(const dario_statement<ppT> &other) const
{
    return (this->commit == other.commit &&
            this->pubpoly == other.pubpoly);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const dario_statement<ppT> &st)
{
    out << st.commit << OUTPUT_NEWLINE;
    out << st.pubpoly << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, dario_statement<ppT> &st)
{
    in >> st.commit;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> st.pubpoly;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool dario_witness<ppT>::operator==(const dario_witness<ppT> &other) const
{
    return (this->polys == other.polys &&
            this->Tpoly == other.Tpoly);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const dario_witness<ppT> &wit)
{
    out << wit.polys << OUTPUT_NEWLINE;
    out << wit.Tpoly << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, dario_witness<ppT> &wit)
{
    in >> wit.polys;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> wit.Tpoly;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool dario_proof<ppT>::operator==(const dario_proof<ppT> &other) const
{
    return (this->commitT == other.commitT &&
            this->commit_prime == other.commit_prime &&
            this->proof_lego == other.proof_lego &&
            this->proof_mue == other.proof_mue);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const dario_proof<ppT> &proof)
{
    out << proof.commitT << OUTPUT_NEWLINE;
    out << proof.commit_prime << OUTPUT_NEWLINE;
    out << proof.proof_lego << OUTPUT_NEWLINE;
    out << proof.proof_mue << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, dario_proof<ppT> &proof)
{
    in >> proof.commitT;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.commit_prime;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.proof_lego;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.proof_mue;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

/******************************** CRS Generator ********************************/

template<typename ppT>
dario_crs<ppT> crs_generator(int &dimension, 
                             int &length, 
                             dario_constraint_system<ppT> &r1cs, 
                             dario_primary_input<ppT> &primary_input, 
                             relation<ppT> &R_link) {

    libff::enter_block("Call to CRS generator");

// CRS Generator: BPC 

    // random element: g1, h, g2, alpha(a), beta(s), gamma(t)
    libff::Fr<ppT> alpha = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> beta = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> gamma = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> delta = libff::Fr<ppT>::random_element();
    libff::G1<ppT> g1 = libff::G1<ppT>::random_element();
    libff::G1<ppT> h = libff::G1<ppT>::random_element();
    libff::G2<ppT> g2 = libff::G2<ppT>::random_element();

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
            // uni_g1_ij.emplace_back(g1 * (beta * i) * (delta * j)) ;
            uni_g1_ij.emplace_back(((delta * j)*(beta * i)) *g1 ) ;
            uni_g1_hat_ij.emplace_back(((beta * i) * (delta * j)) *g1_hat);
        }
        g1_ij.emplace_back(uni_g1_ij);
        g1_hat_ij.emplace_back(uni_g1_hat_ij);
        uni_g1_ij.clear();
        uni_g1_hat_ij.clear();
    }

// CRS Generator: LegoSNARK

    libff::G1_vector<ppT> h_lego; // ck
    lego_ss_keypair<ppT> ss_pair; // (ek, vk) where ek:=[P] = M^T * k and vk:=([C], [a]) s.t.  C = a*k 
    libff::G1_vector<ppT> M; // Matrix M where [x]:=[M]*[w] (x is statement and w is dario_dario_dario_witness, the openings)
    dario_constraint_system<ppT> r1cs_copy(r1cs);

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

    M.emplace_back(h_lego[0]);
    M.emplace_back(libff::G1<ppT>::zero());
    for (size_t i = 1; i < l + 1; i++)
    {
        M.emplace_back(h_lego[i]);
    }
    M.emplace_back(libff::G1<ppT>::zero());
    M.emplace_back(ck_prime.first);
    for (size_t i = 0; i < l; i++)
    {
        M.emplace_back(ck_prime.rest[i]);
    }
    ss_pair = lego_ss_generator<ppT>(M, 2, l + 2);

    R_link = make_commitment<ppT>(h_lego, ck_prime, primary_input);

// Key Generation
    bpc_key<ppT> crs_bpc = bpc_key<ppT>(dimension, length, std::move(g2), std::move(g2_s), std::move(h), std::move(h_s), std::move(g2_hat), std::move(h_hat), std::move(g1_ij), std::move(g1_hat_ij));
    
    lego_cp_snark_keypair<ppT> crs_lego = lego_cp_snark_keypair<ppT>(ss_pair.ek, ss_pair.vk);

    dario_crs<ppT> crs = dario_crs<ppT>(std::move(crs_bpc), std::move(crs_lego));
    crs.print_size();

    return crs;       
}

/******************************** Polynomial Evaluation ********************************/

template<typename ppT>
libff::Fr<ppT> poly_eval(libff::Fr_2dvector<ppT> &poly, 
                         libff::Fr<ppT> &point) {
    libff::Fr<ppT> eval = libff::Fr<ppT>::one();

    // TO DO 
    for(int i=0;i<poly.size();i++) {
        for(int j=0 ; j<poly.size();j++) {
        eval = eval + (poly[i][j] + (point * (libff::Fr<ppT>)i));
        }
    }
    return eval;
}

template<typename ppT>
libff::G1<ppT> poly_eval_G1(libff::Fr_2dvector<ppT> &poly, 
                         libff::Fr<ppT> &point) {
    libff::G1<ppT> eval = libff::G1<ppT>::one();

    // TO DO 
    for(int i=0;i<poly.size();i++) {
        // eval = eval + poly[i] * (point^i);

    }
    return eval;
}

/******************************** Prover ********************************/

template<typename ppT> 
dario_proof<ppT> dario_prover(dario_crs<ppT> &crs, 
                        dario_statement<ppT> &st, 
                        dario_witness<ppT> &wit,
                        dario_primary_input<ppT> &primary_input) {
    
libff::enter_block("Call to Dario Prover");

//R(Polynomial)값을 넣어준다.
    libff::Fr_2dvector<ppT> Rpoly;
    libff::Fr_vector<ppT> uni_Rpoly;

    for (int i=0; i<3; i++) {
        for (int j=0; j<3; j++) {
            uni_Rpoly.emplace_back(libff::Fr<ppT>::random_element());
        }
        Rpoly.emplace_back(uni_Rpoly);
        uni_Rpoly.clear();
    }

//T를 commit하여 C_t를 얻는다.
    bpc_commit<ppT> commitT = bpc_commitment<ppT>(crs.crs_bpc, wit.Tpoly);

//C_t, statement를 hash하여 eval.point인 random를 얻는다.
    int random = sha256<ppT>(as_string<ppT>(st.commit) + as_string<ppT>(st.pubpoly) + as_string<ppT>(commitT));
    libff::Fr<ppT> point = (libff::Fr<ppT>)random;

//Polynomial Evaluation 함수를 통해서 p, r, t`, p_j evaluate
    libff::enter_block("Evaluate Polynomial: p, r, t_prime, p_j");

    // TO DO , invalid evaluation
    libff::G1<ppT> p = poly_eval_G1<ppT>(st.pubpoly, point);
    libff::G1<ppT> r = poly_eval_G1<ppT>(Rpoly, point);
    libff::G1<ppT> t_prime = poly_eval_G1<ppT>(wit.Tpoly, point);
    libff::Fr<ppT> t_prime2 = poly_eval<ppT>(wit.Tpoly, point);
    libff::Fr_2dvector<ppT> p_j;
    libff::Fr_vector<ppT> uni_p_j;

    libff::Fr_2dvector<ppT> wit_poly;

    for(int n=0;n<wit.polys.size()-1;n++) {
        for(int m=0;m<3;m++) {
            wit_poly.emplace_back(wit.polys[m]);
        }
        uni_p_j.emplace_back(poly_eval<ppT>(wit_poly, point));
        p_j.emplace_back(uni_p_j);
        uni_p_j.clear();
    }
    uni_p_j.emplace_back(t_prime2);
    p_j.emplace_back(uni_p_j);
    uni_p_j.clear();

    libff::leave_block("Evaluate Polynomial p, r, t_prime, p_j");

//evaluation 결과를 commit하여 C`, rho` 생성, TO DO
    libff::enter_block("Commit Evaluation");
    bpc_commit<ppT> commit_prime = bpc_commitment(crs.crs_bpc, p_j);
    libff::leave_block("Commit Evaluation");

//MUE-dario_proof 구동
    libff::enter_block("Compute MUE_Proof");

    libff::Fr_2dvector<ppT> pair_poly(wit_poly.size() + wit.Tpoly.size());
    pair_poly = wit.Tpoly;
    pair_poly.insert(pair_poly.end(), wit_poly.begin(), wit_poly.end());
    bpc_commit<ppT> pair_commit = bpc_commitment(crs.crs_bpc, pair_poly);

    libff::Fr<ppT> sumpoint = commitT.rho + wit.rho;

    bpe_statement<ppT> statement_commit = bpe_statement<ppT>(std::move(pair_commit), std::move(commit_prime), std::move(point));
    bpe_witness<ppT> witness_commit = bpe_witness<ppT>(std::move(wit_poly), std::move(p_j), std::move(sumpoint), std::move(commit_prime.rho));
    
    bpe_proof<ppT> proof_commit = bpe_prover(crs.crs_bpc, statement_commit, witness_commit);

    libff::leave_block("Compute MUE_Proof");

//Lego 구동

    libff::enter_block("Compute Lego_Proof");

    libff::G1_vector<ppT> commitments;
    libff::G1<ppT> commitment_prime = commit_prime.commit_hat;
    commitments.emplace_back(p);
    commitments.emplace_back(r);
    commitments.emplace_back(commit_prime.commit);

    statement<ppT> lego_statement = statement<ppT>(std::move(commitments), std::move(commitment_prime));

    libff::Fr_vector<ppT> openings;
    libff::Fr_2dvector<ppT> uni_openings;
    libff::Fr<ppT> opening_prime = commit_prime.rho;

    for(int n=0;n<wit.polys.size()-1;n++) {
        for(int m=0;m<3;m++) {
            uni_openings.emplace_back(wit.polys[m]);
        }
        openings.emplace_back(poly_eval<ppT>(uni_openings, point));
        uni_openings.clear();
    }
    openings.emplace_back(poly_eval<ppT>(wit.Tpoly, point));

    witness<ppT> lego_witness = witness<ppT>(std::move(openings), std::move(opening_prime));
    relation<ppT> lego_relation = relation<ppT> (std::move(lego_statement), std::move(lego_witness));

    lego_cp_snark_proof<ppT> proof_prime = lego_cp_snark_prover<ppT>(std::move(crs.crs_lego.ek), std::move(lego_relation), std::move(primary_input));

    libff::leave_block("Compute Lego_Proof");
    libff::leave_block("Call to Dario Prover");

//dario_proof 반환
    dario_proof<ppT> d_proof = dario_proof<ppT>(std::move(commitT), std::move(commit_prime), std::move(proof_prime), std::move(proof_commit));

    return d_proof;
}

/******************************** Verifier ********************************/
template<typename ppT>
bool dario_verifier(dario_crs<ppT> &crs, 
              dario_statement<ppT> &st, 
              dario_proof<ppT> &dario_proof) {

    libff::enter_block("Call to Dario Verifier");

//C_t, statement를 hash하여 eval.point인 random를 얻는다.
    int random = sha256<ppT>(as_string<ppT>(st.commit) + as_string<ppT>(st.pubpoly) + as_string<ppT>(dario_proof.commitT));
    libff::Fr<ppT> point = (libff::Fr<ppT>)random;

//Polynomial Evaluation 함수를 통해서 p, r evaluate
    libff::enter_block("Polynomial Evaluation: p, r");

//Need to put coef. in Rpoly

    libff::Fr_2dvector<ppT> Rpoly;
    libff::Fr_vector<ppT> uni_Rpoly;

    for (int i=0; i<3; i++) {
        for (int j=0; j<3; j++) {
            uni_Rpoly.emplace_back(libff::Fr<ppT>::random_element());
        }
        Rpoly.emplace_back(uni_Rpoly);
        uni_Rpoly.clear();
    }
    
    libff::G1<ppT> p = poly_eval_G1<ppT>(st.pubpoly, point);
    libff::G1<ppT> r = poly_eval_G1<ppT>(Rpoly, point);

    libff::leave_block("Polynomial Evaluation: p, r");

//MUE에 대한 Verify TO DO 
    libff::enter_block("MUE-Verify");

    bpc_commit<ppT> pair_commit = bpc_commit<ppT>(std::move(dario_proof.commitT.commit + dario_proof.commit_prime.commit), 
                                                  std::move(dario_proof.commitT.commit_hat + dario_proof.commit_prime.commit_hat),
                                                  std::move(dario_proof.commitT.rho + dario_proof.commit_prime.rho));

    bpe_statement<ppT> statement_commit = bpe_statement<ppT>(std::move(pair_commit), std::move(dario_proof.commit_prime), std::move(point));
    
    bool b1 = bpe_verifier(crs.crs_bpc, statement_commit, dario_proof.proof_mue);

    libff::leave_block("MUE-Verify");

//Lego에 대한 Verify
    libff::enter_block("Lego-Verify");

    libff::G1_vector<ppT> commitments;
    libff::G1<ppT> commitment_prime = dario_proof.commit_prime.commit_hat;
    commitments.emplace_back(p);
    commitments.emplace_back(r);
    commitments.emplace_back(dario_proof.commit_prime.commit);

    statement<ppT> lego_statement = statement<ppT>(std::move(commitments), std::move(commitment_prime));

    bool b2 = lego_cp_snark_verifier(crs.crs_lego.vk, lego_statement, dario_proof.proof_lego);

    libff::leave_block("Lego-Verify");

//Verify 결과 반환

    libff::leave_block("Call to Dario Verifier");

    bool result = b1 & b2;
    return result;
}

#endif
}