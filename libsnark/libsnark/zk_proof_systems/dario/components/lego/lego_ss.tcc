

#ifndef LEGO_SS_TCC_
#define LEGO_SS_TCC_

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

namespace libsnark
{
    template <typename ppT>
    void lego_ss_evaluation_key<ppT>::print() const
    {
        libff::print_indent(); printf("* ss_evaluation key\n");
        this->g1_P.print();
    }

    template <typename ppT>
    void lego_ss_verification_key<ppT>::print() const
    {
        libff::print_indent(); printf("* ss_verification key\n");
        printf("g2_a : ");
        this->g2_a.print();
        printf("g2_C : ");
        this->g2_C.print();
    }

    template <typename ppT>
    void lego_ss_keypair<ppT>::print() const
    {
        this->ek.print();
        this->vk.print();
    }

    template <typename ppT>
    void lego_ss_proof<ppT>::print() const
    {
        libff::print_indent(); printf("* ss_proof\n");
        this->g1_pi.print();
    }

    template <typename ppT>
    std::ostream &operator<<(std::ostream &out, const lego_ss_evaluation_key<ppT> &ek)
    {
        out << ek.g1_P << OUTPUT_NEWLINE;

        return out;
    }

    template <typename ppT>
    std::istream &operator>>(std::istream &in, lego_ss_evaluation_key<ppT> &ek)
    {
        in >> ek.g1_P;
        libff::consume_OUTPUT_NEWLINE(in);

        return in;
    }

    template <typename ppT>
    std::ostream &operator<<(std::ostream &out, const lego_ss_verification_key<ppT> &vk)
    {
        out << vk.g2_a << OUTPUT_NEWLINE;
        out << vk.g2_C << OUTPUT_NEWLINE;

        return out;
    }

    template <typename ppT>
    std::istream &operator>>(std::istream &in, lego_ss_verification_key<ppT> &vk)
    {
        in >> vk.g2_a;
        libff::consume_OUTPUT_NEWLINE(in);
        in >> vk.g2_C;
        libff::consume_OUTPUT_NEWLINE(in);

        return in;
    }

    template <typename ppT>
    std::ostream &operator<<(std::ostream &out, const lego_ss_keypair<ppT> &pair)
    {
        out << pair.ek << OUTPUT_NEWLINE;
        out << pair.vk << OUTPUT_NEWLINE;

        return out;
    }

    template <typename ppT>
    std::istream &operator>>(std::istream &in, lego_ss_keypair<ppT> &pair)
    {
        in >> pair.ek;
        libff::consume_OUTPUT_NEWLINE(in);
        in >> pair.vk;
        libff::consume_OUTPUT_NEWLINE(in);

        return in;
    }

    template <typename ppT>
    std::ostream &operator<<(std::ostream &out, const lego_ss_proof<ppT> &proof)
    {
        out << proof.g1_pi << OUTPUT_NEWLINE;

        return out;
    }

    template <typename ppT>
    std::istream &operator>>(std::istream &in, lego_ss_proof<ppT> &proof)
    {
        in >> proof.g1_pi;
        libff::consume_OUTPUT_NEWLINE(in);

        return in;
    }

    template <typename ppT>
    lego_ss_keypair<ppT> lego_ss_generator(const libff::G1_vector<ppT> &M, 
                                           const size_t &l, 
                                           const size_t &t)
    {   
        libff::enter_block("Call to lego_ss_generator");

        libff::Fr_vector<ppT> k;
        libff::Fr<ppT> a = libff::Fr<ppT>::random_element();
        libff::G1_vector<ppT> P;
        libff::G2_vector<ppT> C;
        lego_ss_keypair<ppT> pair;

        k.reserve(l); // size = 2
        P.reserve(t); // size = l+2
        C.reserve(l); // size = 2 
        for (size_t i = 0; i < l; i++)
        {
            k.emplace_back(libff::Fr<ppT>::random_element());
        }
        for (size_t i = 0; i < t; i++)
        {
            P.emplace_back((k[0] * M[i]) + (k[1] * M[l + 2 + i])); 
        }
        for (size_t i = 0; i < l; i++)
        {
            C.emplace_back(a * k[i] * (libff::G2<ppT>::one()));
        }
        libff::G2<ppT> g2_a = a * (libff::G2<ppT>::one());

        pair.ek.g1_P = P;
        pair.vk.g2_C = C;
        pair.vk.g2_a = g2_a;

        libff::leave_block("Call to lego_ss_generator");

        return pair;
    }

    template <typename ppT>
    lego_ss_proof<ppT> lego_ss_prover(const lego_ss_evaluation_key<ppT> &ek,
                                      const libff::G1_vector<ppT> &x,
                                      const libff::Fr_vector<ppT> &w)
    {
        libff::enter_block("Call to lego_ss_prover");

        libff::G1<ppT> pi = libff::G1<ppT>::zero();
        for (size_t i = 0; i < w.size(); i++)
        {
            pi = pi + (w[i] * ek.g1_P[i]);
        }

        libff::leave_block("Call to lego_ss_prover");

        return lego_ss_proof<ppT>(std::move(pi));
    }
    
    template <typename ppT>
    bool lego_ss_verifier(const lego_ss_verification_key<ppT> &vk,
                          const libff::G1_vector<ppT> &x, 
                          const lego_ss_proof<ppT> &proof)
    {
        libff::enter_block("Call to lego_ss_verifier");
        
        libff::GT<ppT> check;
        libff::GT<ppT> check2;

        check = ppT::reduced_pairing(x[0],vk.g2_C[0]) * ppT::reduced_pairing(x[1],vk.g2_C[1]);
        check2 = ppT::reduced_pairing(proof.g1_pi, vk.g2_a);
        
        libff::leave_block("Call to lego_ss_verifier");

        return (check==check2);
    }
} // namespace libsnark

#endif