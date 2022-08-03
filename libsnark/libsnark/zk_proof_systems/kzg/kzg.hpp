/** @file
*****************************************************************************

Declaration of Kate Polynomial Commitment in the generic group (GG) model.

This includes:
- class for commitment key
- class for commitment
- class for witness
- class for polynomial
- PK generator algorithm
- commit algorithm
- (create witness = evaluation) algorithm
- evaluation verifier algorithm

The implementation instantiates the protocol of \[KZG10].

Acronyms:

- vCNN+ = "Committed verifiable Convolutional Neural Network"

References:

\[KZG10]:
 "Polynomial Commitments",
 Aniket Kate, Gregory M. Zaverucha, Ian Goldberg
 ASIACRYPT 2010,
 <https://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf>

*****************************************************************************
* @author     This file is part of libsnark, developed by SCIPR Lab
*             and contributors (see AUTHORS).
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#ifndef KZG_HPP_
#define KZG_HPP_

namespace libsnark
{

/******************************** Commitment key ********************************/
template<typename ppT>
class commitkey;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const commitkey<ppT> &ck);

template<typename ppT>
std::istream& operator>>(std::istream &in, commitkey<ppT> &ck);

template <typename ppT>
class commitkey
{
    public:
    libff::G1_vector<ppT> g1;
    libff::G2_vector<ppT> g2;
    libff::Fr<ppT> a;

    commitkey() = default;
    commitkey<ppT>& operator=(const commitkey<ppT> &other) = default;
    commitkey(const commitkey<ppT> &other) = default;
    commitkey(commitkey<ppT> &&other) = default;
    commitkey(
        libff::G1_vector<ppT> &&g1,
        libff::G2_vector<ppT> &&g2,
        libff::Fr<ppT> &&a) :
    g1(std::move(g1)),
    g2(std::move(g2)),
    a(std::move(a)) 
    {};

    size_t G1_size() const
    {
        return g1.size();
    }

    size_t GT_size() const
    {
        return 1;
    }

    size_t size_in_bits() const
    {
       return (g1.size_in_bits() + GT_size() * libff::GT<ppT>::size_in_bits());
    }

    void print_size() const
    {
        libff::print_indent(); printf("* G1 elements in CK: %zu\n", this->G1_size());
        libff::print_indent(); printf("* GT elements in CK: %zu\n", this->GT_size());
        libff::print_indent(); printf("* Commit Key size in bits: %zu\n", this->size_in_bits());
    }

    bool operator==(const commitkey<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const commitkey<ppT> &ck);
    friend std::istream& operator>> <ppT>(std::istream &in, commitkey<ppT> &ck);
};

/******************************** Commitment ********************************/

template<typename ppT>
class commitment;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const commitment<ppT> &ck);

template<typename ppT>
std::istream& operator>>(std::istream &in, commitment<ppT> &ck);

template <typename ppT>
class commitment
{
    public:
    libff::G1<ppT> g1;
    libff::G2<ppT> g2;

    commitment() = default;
    commitment<ppT>& operator=(const commitment<ppT> &other) = default;
    commitment(const commitment<ppT> &other) = default;
    commitment(commitment<ppT> &&other) = default;
    commitment(
        libff::G1<ppT> &&g1,
        libff::G2<ppT> &&g2) :
    g1(std::move(g1)),
    g2(std::move(g2)) 
    {};

    size_t G1_size() const
    {
        return g1.size();
    }

    size_t GT_size() const
    {
        return 1;
    }

    size_t size_in_bits() const
    {
       return (g1.size_in_bits() + GT_size() * libff::GT<ppT>::size_in_bits());
    }

    void print_size() const
    {
        libff::print_indent(); printf("* G1 elements in CK: %zu\n", this->G1_size());
        libff::print_indent(); printf("* GT elements in CK: %zu\n", this->GT_size());
        libff::print_indent(); printf("* Commit Key size in bits: %zu\n", this->size_in_bits());
    }

    bool operator==(const commitment<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const commitment<ppT> &ck);
    friend std::istream& operator>> <ppT>(std::istream &in, commitment<ppT> &ck);
};

/******************************** Polynomial ********************************/

/******************************** Witness ********************************/
template<typename ppT>
class witness;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const witness<ppT> &wit);

template<typename ppT>
std::istream& operator>>(std::istream &in, witness<ppT> &wit);

template <typename ppT>
class witness
{
    public:
    libff::Fr<ppT> point;
    libff::Fr<ppT> eval;
    libff::Fr_vector<ppT> psi; //need to be deleted
    libff::G1<ppT> w;
    libff::G2<ppT> w2; //need to be deleted.

    witness() = default;
    witness<ppT>& operator=(const witness<ppT> &other) = default;
    witness(const witness<ppT> &other) = default;
    witness(witness<ppT> &&other) = default;
    witness(
        libff::Fr<ppT> &&point,
        libff::Fr<ppT> &&eval,
        libff::Fr_vector<ppT> &&psi,
        libff::G1<ppT> &&w,
        libff::G2<ppT> &&w2):

    point(std::move(point)),
    eval(std::move(eval)),
    psi(std::move(psi)),
    w(std::move(w)),
    w2(std::move(w2))
    {};

    size_t G1_size() const
    {
        return w.size();
    }

    size_t GT_size() const
    {
        return 1;
    }

    size_t size_in_bits() const
    {
       return (w.size_in_bits() + GT_size() * libff::GT<ppT>::size_in_bits());
    }

    void print_size() const
    {
        libff::print_indent(); printf("* G1 elements in CK: %zu\n", this->G1_size());
        libff::print_indent(); printf("* GT elements in CK: %zu\n", this->GT_size());
        libff::print_indent(); printf("* Commit Key size in bits: %zu\n", this->size_in_bits());
    }

    bool operator==(const witness<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const witness<ppT> &wit);
    friend std::istream& operator>> <ppT>(std::istream &in, witness<ppT> &wit);
};

/***************************** Main algorithms *******************************/

/**
 * A setup algorithm for the KZG10.
 *
 * Given an authority t: degree, this algorithm produces commitment key, which is a t-SDH tuple.
 */
// template<typename ppT>
// libff::G1_vector<ppT> kzg_setup(int t);

template<typename ppT>
// libff::G1_vector<ppT> kzg_setup(int t);
commitkey<ppT> kzg_setup(int t);

/**
 * A commit algorithm for the KZG10.
 *
 * Given a public key and polynomial, this algorithm
 * produces a commitment of the polynomial.
 */
template<typename ppT>
// libff::G1<ppT> kzg_commit(libff::G1_vector<ppT> &ck, libff::Fr_vector<ppT> &poly, int t);
commitment<ppT> kzg_commit(commitkey<ppT> &ck, libff::Fr_vector<ppT> &poly, int t);

/**
 * A witness-generate algorithm for the KZG10.
 *
 * Given a public key, polynomial, and evaluation point, this algorithm produces a witness of the evaluation of the polynomial.
 * (It proves that Polynomial is evaluated at particular evaluation point)
 */
template<typename ppT>
// witness<ppT> kzg_witness(libff::G1_vector<ppT> &ck, libff::Fr_vector<ppT> &poly, libff::Fr<ppT> &point, int t);
witness<ppT> kzg_witness(commitkey<ppT> &ck, libff::Fr_vector<ppT> &poly, libff::Fr<ppT> &point, int t);

template<typename ppT>
libff::Fr<ppT> convert(int t);

 /**
 * A Evaluation Verifier algorithm for the KZG10.
 *
 * Given a public key, commitment,and witness, this algorithm verifies the following statement.
 * "Polynomial is evaluated at particular evaluation point."
 */
template<typename ppT>
bool kzg_vfyeval(commitkey<ppT> &ck, commitment<ppT> &commit, witness<ppT> &witness);


/**
 This is the consistency check between the intermediate clauses of verify-pairing equation.
   To run this check, change of Data Structure is required. The change is as follows.

 - commitment key: secret randomness A needed
 - commit: G1-version, G2-version both needed
 - witness: psi[i], witness(G2-version needed)
 - polynomial
 
 */
template<typename ppT>
bool kzg_testvfy(commitkey<ppT> &ck, commitment<ppT> &commit, witness<ppT> &witness, libff::Fr_vector<ppT> &poly, int t);

} //libsnark

#include <libsnark/zk_proof_systems/kzg/kzg.tcc>

#endif // KZG_HPP_