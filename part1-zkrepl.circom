pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";

// Copying BinaryMerkleRoot template b/c we cannot import `@zk-kit/binary-merkle-root.circom/src/binary-merkle-root.circom` in zkrepl
// https://github.com/privacy-scaling-explorations/zk-kit.circom/blob/main/packages/binary-merkle-root/src/binary-merkle-root.circom
template BinaryMerkleRoot(MAX_DEPTH) {
    signal input leaf, depth, indices[MAX_DEPTH], siblings[MAX_DEPTH];

    signal output out;

    signal nodes[MAX_DEPTH + 1];
    nodes[0] <== leaf;

    signal roots[MAX_DEPTH];
    var root = 0;

    for (var i = 0; i < MAX_DEPTH; i++) {
        var isDepth = IsEqual()([depth, i]);

        roots[i] <== isDepth * nodes[i];

        root += roots[i];

        var c[2][2] = [ [nodes[i], siblings[i]], [siblings[i], nodes[i]] ];
        var childNodes[2] = MultiMux1(2)(c, indices[i]);

        nodes[i + 1] <== Poseidon(2)(childNodes);
    }

    var isDepth = IsEqual()([depth, MAX_DEPTH]);

    out <== root + isDepth * nodes[MAX_DEPTH];
}

template PODContainsKV () {
    var maxDepth = 10; // configurable

    signal input podID; // content ID of POD
    signal input R8x, R8y, S; // EdDSA signature
    signal input Ax, Ay; // EdDSA public keyHash
    signal input keyHash, valueHash;
    signal input depth, index, siblings[maxDepth];
    
    // Checks valid POD signature
    EdDSAPoseidonVerifier()(
        1,
        Ax,
        Ay,
        S,
        R8x,
        R8y,
        podID
    );

    signal indices[maxDepth] <== Num2Bits(maxDepth)(index);
    signal expectedPodID <== BinaryMerkleRoot(maxDepth)(
        keyHash,
        depth,
        indices,
        siblings
    );
    podID === expectedPodID;
    valueHash === siblings[0];

    log("All constraints passed!");
}

component main { public [ keyHash, valueHash, Ax, Ay ] } = PODContainsKV();

/*

Inputs below generated from a real POD
{
  entries: {
    A: 123,
    B: 321,
    C: 'hello',
    D: 'foobar',
    E: { cryptographic: 123 },
    F: {
      cryptographic: '0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000'
    },
    G: 7,
    H: 8,
    I: 9,
    J: 10,
    K: -5,
    owner: {
      cryptographic: '0x295e47b5d8ead41bbb4b9fe30ba1da0f1eaf8d5146cf0d7153d1878cb2908951'
    }
  },
  signature: 'Nz4tfb9jGmbneh/qwefejCd2iJ/JaOHX8pZz8MZqNxmA9SZbJvjfoePSju2oKM52ydpTwWFuMc0Bg2fLcEygAw',
  signerPublicKey: 'xDP3ppa3qjpSJO+zmTuvDM2eku7O4MKaP2yCCKnoHZ4'
}

*/


/* INPUT = {
    "podID": "12270358673359082965738807859874919382499710065761285952062666579568565718653",
    "Ax": "13277427435165878497778222415993513565335242147425444199013288855685581939618",
    "Ay": "13622229784656158136036771217484571176836296686641868549125388198837476602820",
    "R8x": "7992821217327622955890465279229121725074281617714658027486909914621548371074",
    "R8y": "11405734751649171564583675673630564127815711985187113530077637798277417877047",
    "S": "1640161649771700932833151683605766558948110094112079974586279748238737601920",
    "keyHash": "151251200029686127063327095456320040687905427497336635391695211041155747807",
    "valueHash": "9904028930859697121695025471312564917337032846528014134060777877259199866166",
    "depth": "5",
    "index": "0",
    "siblings": [
        "9904028930859697121695025471312564917337032846528014134060777877259199866166",
        "3061484723492332507965148030160360459221544214848710312076669786481227696312",
        "1034918093316386824116250922167450510848513309806370785803679707656130099343",
        "1967460137183576823935940165748484233277693357918661365351807577356270673444",
        "17807035268217408168284551891421581960582995627579868198916345027521558073672",
        "0",
        "0",
        "0",
        "0",
        "0"
    ]
} */