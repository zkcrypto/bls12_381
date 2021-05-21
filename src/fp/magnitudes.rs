#![allow(dead_code)]

pub struct U1;
pub struct U2;
pub struct U3;
pub struct U4;
pub struct U5;
pub struct U6;
pub struct U7;
pub struct U8;
pub struct U9;

pub trait Magnitude {
    const P: [u64; 6];
    const P2: [u64; 12];
    const U64: u64;
}
impl Magnitude for U1 {
    const P: [u64; 6] = super::MODULUS;
    const P2: [u64; 12] = [
        0x26aa00001c718e39,
        0x7ced6b1d76382eab,
        0x162c338362113cfd,
        0x66bf91ed3e71b743,
        0x292e85a87091a049,
        0x1d68619c86185c7b,
        0xf53149330978ef01,
        0x50a62cfd16ddca6e,
        0x66e59e49349e8bd0,
        0xe2dc90e50e7046b4,
        0x4bd278eaa22f25e9,
        0x2a437a4b8c35fc7,
    ];
    const U64: u64 = 1;
}
impl Magnitude for U2 {
    const P: [u64; 6] = [
        0x73fdffffffff5556,
        0x3d57fffd62a7ffff,
        0xce61a541ed61ec48,
        0xc8ee9709e70a257e,
        0x96374f6c869759ae,
        0x340223d472ffcd34,
    ];
    const P2: [u64; 12] = [
        0x4d54000038e31c72,
        0xf9dad63aec705d56,
        0x2c586706c42279fa,
        0xcd7f23da7ce36e86,
        0x525d0b50e1234092,
        0x3ad0c3390c30b8f6,
        0xea62926612f1de02,
        0xa14c59fa2dbb94dd,
        0xcdcb3c92693d17a0,
        0xc5b921ca1ce08d68,
        0x97a4f1d5445e4bd3,
        0x5486f497186bf8e,
    ];
    const U64: u64 = 2;
}
impl Magnitude for U3 {
    const P: [u64; 6] = [
        0x2dfcffffffff0001,
        0x5c03fffc13fbffff,
        0x359277e2e412e26c,
        0x2d65e28eda8f383e,
        0xe152f722c9e30686,
        0x4e0335beac7fb3ce,
    ];
    const P2: [u64; 12] = [
        0x73fe00005554aaab,
        0x76c8415862a88c01,
        0x42849a8a2633b6f8,
        0x343eb5c7bb5525c9,
        0x7b8b90f951b4e0dc,
        0x583924d592491571,
        0xdf93db991c6acd03,
        0xf1f286f744995f4c,
        0x34b0dadb9ddba370,
        0xa895b2af2b50d41d,
        0xe3776abfe68d71bd,
        0x7eca6ee2a4a1f55,
    ];
    const U64: u64 = 3;
}
impl Magnitude for U4 {
    const P: [u64; 6] = [
        0xe7fbfffffffeaaac,
        0x7aaffffac54ffffe,
        0x9cc34a83dac3d890,
        0x91dd2e13ce144afd,
        0x2c6e9ed90d2eb35d,
        0x680447a8e5ff9a69,
    ];
    const P2: [u64; 12] = [
        0x9aa8000071c638e4,
        0xf3b5ac75d8e0baac,
        0x58b0ce0d8844f3f5,
        0x9afe47b4f9c6dd0c,
        0xa4ba16a1c2468125,
        0x75a18672186171ec,
        0xd4c524cc25e3bc04,
        0x4298b3f45b7729bb,
        0x9b967924d27a2f41,
        0x8b72439439c11ad1,
        0x2f49e3aa88bc97a7,
        0xa90de92e30d7f1d,
    ];
    const U64: u64 = 4;
}
impl Magnitude for U5 {
    const P: [u64; 6] = [
        0xa1fafffffffe5557,
        0x995bfff976a3fffe,
        0x03f41d24d174ceb4,
        0xf6547998c1995dbd,
        0x778a468f507a6034,
        0x820559931f7f8103,
    ];
    const P2: [u64; 12] = [
        0xc15200008e37c71d,
        0x70a317934f18e957,
        0x6edd0190ea5630f3,
        0x1bdd9a23838944f,
        0xcde89c4a32d8216f,
        0x9309e80e9e79ce67,
        0xc9f66dff2f5cab05,
        0x933ee0f17254f42a,
        0x27c176e0718bb11,
        0x6e4ed47948316186,
        0x7b1c5c952aebbd91,
        0xd3516379bd0dee4,
    ];
    const U64: u64 = 5;
}
impl Magnitude for U6 {
    const P: [u64; 6] = [
        0x5bf9fffffffe0002,
        0xb807fff827f7fffe,
        0x6b24efc5c825c4d8,
        0x5acbc51db51e707c,
        0xc2a5ee4593c60d0c,
        0x9c066b7d58ff679d,
    ];
    const P2: [u64; 12] = [
        0xe7fc0000aaa95556,
        0xed9082b0c5511802,
        0x850935144c676df0,
        0x687d6b8f76aa4b92,
        0xf71721f2a369c1b8,
        0xb07249ab24922ae2,
        0xbf27b73238d59a06,
        0xe3e50dee8932be99,
        0x6961b5b73bb746e1,
        0x512b655e56a1a83a,
        0xc6eed57fcd1ae37b,
        0xfd94ddc54943eab,
    ];
    const U64: u64 = 6;
}
impl Magnitude for U7 {
    const P: [u64; 6] = [
        0x15f8fffffffdaaad,
        0xd6b3fff6d94bfffe,
        0xd255c266bed6bafc,
        0xbf4310a2a8a3833b,
        0x0dc195fbd711b9e3,
        0xb6077d67927f4e38,
    ];
    const P2: [u64; 12] = [
        0xea60000c71ae38f,
        0x6a7dedce3b8946ae,
        0x9b356897ae78aaee,
        0xcf3cfd7cb51c02d5,
        0x2045a79b13fb6201,
        0xcddaab47aaaa875e,
        0xb4590065424e8907,
        0x348b3aeba0108908,
        0xd04754007055d2b2,
        0x3407f6436511eeee,
        0x12c14e6a6f4a0965,
        0x127d85810d579e73,
    ];
    const U64: u64 = 7;
}
impl Magnitude for U8 {
    const P: [u64; 6] = [
        0xcff7fffffffd5558,
        0xf55ffff58a9ffffd,
        0x39869507b587b120,
        0x23ba5c279c2895fb,
        0x58dd3db21a5d66bb,
        0xd0088f51cbff34d2,
    ];
    const P2: [u64; 12] = [
        0x35500000e38c71c8,
        0xe76b58ebb1c17559,
        0xb1619c1b1089e7eb,
        0x35fc8f69f38dba18,
        0x49742d43848d024b,
        0xeb430ce430c2e3d9,
        0xa98a49984bc77808,
        0x853167e8b6ee5377,
        0x372cf249a4f45e82,
        0x16e48728738235a3,
        0x5e93c75511792f4f,
        0x1521bd25c61afe3a,
    ];
    const U64: u64 = 8;
}
impl Magnitude for U9 {
    const P: [u64; 6] = [
        0x89f6fffffffd0003,
        0x140bfff43bf3fffd,
        0xa0b767a8ac38a745,
        0x8831a7ac8fada8ba,
        0xa3f8e5685da91392,
        0xea09a13c057f1b6c,
    ];
    const P2: [u64; 12] = [
        0x5bfa0000fffe0001,
        0x6458c40927f9a404,
        0xc78dcf9e729b24e9,
        0x9cbc215731ff715b,
        0x72a2b2ebf51ea294,
        0x8ab6e80b6db4054,
        0x9ebb92cb5540670a,
        0xd5d794e5cdcc1de6,
        0x9e129092d992ea52,
        0xf9c1180d81f27c57,
        0xaa66403fb3a85538,
        0x17c5f4ca7ede5e01,
    ];
    const U64: u64 = 9;
}
