pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "./tree.circom";

// This circuit uses poseidon and mux1


//This function calculates the secret using identityNullifier and identityTrapdoor as private inputs
template CalculateSecret() {
    signal input identityNullifier; //private input
    signal input identityTrapdoor;  // private input inputs
    signal output out;

    component poseidon = Poseidon(2);

    poseidon.inputs[0] <== identityNullifier;
    poseidon.inputs[1] <== identityTrapdoor;

    out <== poseidon.out;
}
/*this function calculates the 
identity commitment by taking the hash
of an EdDSA public key and the secrets */
template CalculateIdentityCommitment() {
    signal input secret; // private input 

    signal output out;

    component poseidon = Poseidon(1);

    poseidon.inputs[0] <== secret;

    out <== poseidon.out;
}

/*this function hashes the nullifierHash
 with th externalnullifier as public input and
 the identityNullifier as private inputs
*/
template CalculateNullifierHash() {
    signal input externalNullifier; //public input
    signal input identityNullifier; // private input

    signal output out;

    component poseidon = Poseidon(2);

    poseidon.inputs[0] <== externalNullifier;
    poseidon.inputs[1] <== identityNullifier;

    out <== poseidon.out;
}

// nLevels must be < 32.
template Semaphore(nLevels) {
    signal input identityNullifier; //private input
    signal input identityTrapdoor;  //private input
    signal input treePathIndices[nLevels]; //private input merkle path to the identity commitment
    signal input treeSiblings[nLevels];

    signal input signalHash; // public input
    signal input externalNullifier; // public input

    signal output root; // public input
    signal output nullifierHash; // public input


    // calculating the secret
    component calculateSecret = CalculateSecret();
    calculateSecret.identityNullifier <== identityNullifier;
    calculateSecret.identityTrapdoor <== identityTrapdoor;

    signal secret;
    secret <== calculateSecret.out;

    // calculating the identity commitment
    component calculateIdentityCommitment = CalculateIdentityCommitment();
    calculateIdentityCommitment.secret <== secret;

   // calculating the nullifier hash
    component calculateNullifierHash = CalculateNullifierHash();
    calculateNullifierHash.externalNullifier <== externalNullifier;
    calculateNullifierHash.identityNullifier <== identityNullifier;
     
     // running the merkle inclusion proof
    component inclusionProof = MerkleTreeInclusionProof(nLevels);
    inclusionProof.leaf <== calculateIdentityCommitment.out;

    for (var i = 0; i < nLevels; i++) {
        inclusionProof.siblings[i] <== treeSiblings[i];
        inclusionProof.pathIndices[i] <== treePathIndices[i];
    }

    root <== inclusionProof.root;

    // Dummy square to prevent tampering signalHash.
    signal signalHashSquared;
    signalHashSquared <== signalHash * signalHash;

    nullifierHash <== calculateNullifierHash.out;
}
/* taking in two public input
signalHash and externalNullifier to compute the semaphore signaling*/
component main {public [signalHash, externalNullifier]} = Semaphore(20);
