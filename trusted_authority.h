#ifndef TRUSTED_AUTHORITY_H
#define TRUSTED_AUTHORITY_H

#include <vector>
#include "Algorithm/pairing_3.h"
#include "multi_issuer.h"

using namespace std;

// 1. TA公钥结构 (全部在 G1 上)
struct TAPublicKey {
    G1 X;           // X = x_{TA} * G1_gen
    G1 Y_x;         // Y_x = y_x * G1_gen
    vector<G1> Y;   // Y_i = y_i * G1_gen
};

// 2. TA私钥结构 (在 Z_p 上)
struct TAPrivateKey {
    Big x_TA;
    Big y_x;
    vector<Big> y;
};

struct TAKeyPair {
    TAPublicKey pk;
    TAPrivateKey sk;
};

// 3. TA签名结构 (在 G2 上)
struct TASignature {
    G2 R;
    G2 S;
};

// 4. 盲化后的数据组合 (给验证者)
struct RandomizedCredential {
    G2 apk_x_prime;
    vector<G2> apk_Y_prime;
    G2 R_prime;
    G2 S_prime;
};

// 函数声明
TAKeyPair generateTAKeyPair(int num_messages, PFC* pfc, const G1& G1_gen);
TASignature signAggregatedPK(const TAKeyPair& ta_kp, const AggregatedPK& apk, PFC* pfc, const G2& G2_gen);
RandomizedCredential randomizeCredential(const AggregatedPK& apk, const TASignature& sig, PFC* pfc);
bool verifyRandomizedCredential(const TAPublicKey& ta_pk, const RandomizedCredential& cred, PFC* pfc, const G1& G1_gen);

#endif // TRUSTED_AUTHORITY_H
