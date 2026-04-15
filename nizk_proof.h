#ifndef NIZK_PROOF_H
#define NIZK_PROOF_H

#include <string>
#include "Algorithm/pairing_3.h"

using namespace std;

// 1. 验证者的密钥对
struct VerifierKeyPair {
    Big sk_V;
    G2 pk_V;   // pk_V = sk_V * G2_gen
};

// 2. NIZK 证明结构
struct NIZKProof {
    Big c; // 挑战
    Big z; // 响应
};

// 函数声明
VerifierKeyPair generateVerifierKeyPair(PFC* pfc, const G2& G2_gen);
NIZKProof generateNIZKProof(const string& id_V, const VerifierKeyPair& kp, PFC* pfc, const G2& G2_gen);
bool verifyNIZKProof(const string& id_V, const G2& pk_V, const NIZKProof& proof, PFC* pfc, const G2& G2_gen);

#endif // NIZK_PROOF_H
