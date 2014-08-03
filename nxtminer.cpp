// Original Author: Doctor Evil
// License: GNU General Public License, version 3
// Status: Working proof of concept
//
#include <string.h>
#include <iostream>
#include <string>
#include <fstream>
#include <map>
#include <vector>
#include <boost/format.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "curve25519-donna-c64.c"

#define BATCH_SIZE 256

typedef std::basic_string<unsigned char> bytestring;

unsigned char *sha256(unsigned char *str, int n, unsigned char *hash)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, n);
    SHA256_Final(hash, &sha256);
    return hash;
}

bytestring unhex(const char* input)
{
    bytestring output;
    output.reserve(strlen(input) / 2);
    (void) boost::algorithm::unhex(input, std::back_inserter(output));
    return output;
}

std::string hex(const bytestring &input)
{
    std::string output;
    output.reserve(input.size() * 2);
    (void) boost::algorithm::hex(input, std::back_inserter(output));
    return output;
}

std::string hex(const felem e)
{
    bytestring s(32, 0);
    fcontract(&s[0], e);
    return hex(s);
}

boost::multiprecision::cpp_int le32_to_cpp_int(const bytestring &le32)
{
    boost::multiprecision::cpp_int mpi(0);
    for ( int i = le32.size(); i >= 0; i-- ) {
        mpi = (mpi << 8) + le32[i];
    }
    return mpi;
}

// Computes (exponent_le32 * 2^doublings) % group_order
boost::multiprecision::cpp_int compute_exponent(const bytestring &exponent_le32, uint64_t doublings)
{
    boost::multiprecision::cpp_int pow(doublings);
    boost::multiprecision::cpp_int mod("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"); // group order
    boost::multiprecision::cpp_int base(2);
    boost::multiprecision::cpp_int result = powm(base, pow, mod);
    result = result * le32_to_cpp_int(exponent_le32);
    result = result % mod;
    return result;
}

// Point doubling; See http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#doubling-mdbl-1987-m
void xz_ge_double(felem xout, felem zout, const felem xin)
{
    static const felem fone = {1};
    felem xx1, t0, t1, t2;
    fsquare_times(xx1, xin, 1);
    fcopy(t0, fone);
    fdifference_backwards(t0, xx1);
    fsquare_times(xout, t0, 1);
    fscalar_product(t1, xin, 486662);
    fsum(t1, xx1);
    fsum(t1, fone);
    fmul(t2, xin, t1);
    fscalar_product(zout, t2, 4);
}

// Simultaneous modular inversion; See Section 2.25 of Guide to Elliptic Curve Cryptography (2004)
void batch_inverse(felem *a, int n)
{
    felem c[BATCH_SIZE];
    fcopy(c[0], a[0]);
    for ( int i = 1; i < n; i ++ ) {
        fmul(c[i], c[i-1], a[i]);
    }
    felem u;
    crecip(u, c[n - 1]);
    for ( int i = n - 1; i > 0; i-- ) {
        felem t1, t2;
        fmul(t1, u, c[i-1]);
        fmul(t2, u, a[i]);
        fcopy(a[i], t1);
        fcopy(u, t2);
    }
    fcopy(a[0], u);
}

boost::recursive_mutex guard;

uint64_t checked = 0;

class MinerFunctor {
public:
    void operator()(std::map<uint64_t, uint64_t> &accounts, std::string thread_seed) {
        // Our approach is to pick a random point and repeatedly double it.
        // This is cheaper than the more naive approach of multiplying the
        // generator point times random exponents.
        // We work in batches because our point doubling algorithm requires a
        // modular inversion which is more efficiently computed in batches.
        const int n = BATCH_SIZE;
        felem xs[BATCH_SIZE], zs[BATCH_SIZE];
        std::vector<bytestring> exponents;
        static const unsigned char generator[32] = {9};
        for ( int i = 0; i < n; i++ ) {
            bytestring exponent(32, 0);
            std::string exponent_seed = boost::str(boost::format("%1%:%2%") % thread_seed % i);
            sha256((unsigned char*) &exponent_seed[0], exponent_seed.size(), &exponent[0]);
            // transform initial exponent according to curve25519 tweaks
            exponent[0] &= 248;
            exponent[31] &= 127;
            exponent[31] |= 64;
            uint8_t pubkey[32];
            curve25519_donna(pubkey, &exponent[0], generator);
            fexpand(xs[i], pubkey);
            exponents.push_back(exponent);
        }
        for ( uint64_t doublings = 1; true; doublings++ ) {
            for ( int i = 0; i < n; i++ ) {
                felem xout;
                xz_ge_double(xout, zs[i], xs[i]);
                fcopy(xs[i], xout);
            }
            batch_inverse(zs, n);
            for ( int i = 0; i < n; i++ ) {
                felem xout;
                fmul(xout, xs[i], zs[i]);
                uint8_t pubkey[32], pubkey_hash[32];
                fcontract(pubkey, xout);
                // not entirely sure normalizing the representation of x is necessary but can't hurt
                fexpand(xout, pubkey);
                fcopy(xs[i], xout);
                sha256(pubkey, 32, pubkey_hash);
                uint64_t account_id = *((uint64_t*) pubkey_hash);
                if ( accounts.count(account_id) ) {
                    boost::lock_guard<boost::recursive_mutex> lock(guard);
                    boost::multiprecision::cpp_int e = compute_exponent(exponents[i], doublings);
                    std::cout << "found " << accounts[account_id] << " NXT in account " << account_id << std::endl;
                    std::cout << "  secret exponent = " << e << std::endl;
                }
            }
            checked += n;
        }
    }
};

int main(int argc, char* argv[])
{
    if ( argc < 2 ) {
        std::cerr << "Usage: nxtminer <accounts-file> [random-seed]" << std::endl;
        exit(1);
    }
    bytestring binary_seed(16, 0);
    RAND_pseudo_bytes(&binary_seed[0], 16);
    std::string random_seed = hex(binary_seed);
    if ( argc == 3 ) {
        random_seed = std::string(argv[2]);
    }

    // load a file with "<account-id> <balance>" darknxt records
    std::map<uint64_t, uint64_t> accounts;
    std::ifstream accounts_file(argv[1]);
    if ( !accounts_file ) {
        std::cerr << "could not open" << argv[1] << std::endl;
        exit(1);
    }
    for ( std::string line; std::getline(accounts_file, line); ) {
        uint64_t account_id, balance;
        std::stringstream linestream(line);
        linestream >> account_id >> balance;
        accounts[account_id] = balance;
    }

    // fire up as many worker threads as we have cores
    int num_threads = boost::thread::hardware_concurrency();
    boost::thread_group workers;
    MinerFunctor f;
    for ( int n = 0; n < num_threads; n++ ) {
        std::string thread_seed = boost::str(boost::format("%1%:%2%") % random_seed % n);
        workers.create_thread(boost::bind<void>(f, boost::ref(accounts), thread_seed));
    }

    std::cout << "using seed: " << random_seed << std::endl;
    std::cout << "searching " << accounts.size() << " accounts" << std::endl;
    std::cout << "calibrating ... " << std::flush;
    boost::this_thread::sleep(boost::posix_time::seconds(10));
    std::cout << checked/10 << " keys/sec" << std::endl;

    workers.join_all();

    return 0;
}
