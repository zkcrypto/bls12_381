// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]

use bls12_381::Scalar;

risc0_zkvm::guest::entry!(main);

fn main() {
    // const LARGEST: Scalar = Scalar([
    //     0xffff_ffff_0000_0000,
    //     0x53bd_a402_fffe_5bfe,
    //     0x3339_d808_09a1_d805,
    //     0x73ed_a753_299d_7d48,
    // ]);
    const LARGEST: Scalar = Scalar::set_raw([
        0xffff_ffff_0000_0000,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ]);

    let mut tmp = LARGEST;
    tmp += &LARGEST;

    assert_eq!(
        tmp,
        // Scalar([
        //     0xffff_fffe_ffff_ffff,
        //     0x53bd_a402_fffe_5bfe,
        //     0x3339_d808_09a1_d805,
        //     0x73ed_a753_299d_7d48,
        // ])
        Scalar::set_raw([
            0xffff_fffe_ffff_ffff,
            0x53bd_a402_fffe_5bfe,
            0x3339_d808_09a1_d805,
            0x73ed_a753_299d_7d48,
        ])
    );

    let mut tmp = LARGEST;
    // tmp += &Scalar([1, 0, 0, 0]);
    tmp += &Scalar::set_raw([1, 0, 0, 0]);

    assert_eq!(tmp, Scalar::zero());
}
