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

fn t_modadd() {
    const LARGEST: Scalar = Scalar::from_raw([
        0xffff_ffff_0000_0000,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ]);

    let mut tmp = LARGEST;
    tmp += &LARGEST;
    assert_eq!(
        tmp,
        Scalar::from_raw([
            0xffff_fffe_ffff_ffff,
            0x53bd_a402_fffe_5bfe,
            0x3339_d808_09a1_d805,
            0x73ed_a753_299d_7d48,
        ])
    );

    let mut tmp = LARGEST;
    tmp += &Scalar::from_raw([1, 0, 0, 0]);
    assert_eq!(tmp, Scalar::zero());
}

fn t_modmul() {
    const THREE: Scalar = Scalar::from_raw([3, 0, 0, 0]);
    let mut val = Scalar::from_raw([1, 0, 0, 0]);
    let mut prod = 1;
    for j in 0..40 {
      val *= &THREE;
      prod *= 3;
      assert_eq!(val, Scalar::from_raw([prod,0,0,0]));
    }
}

fn t_modinv() {
    const TWO: Scalar = Scalar::from_raw([2, 0, 0, 0]);
    let result = Scalar::invert(&TWO).unwrap();
    assert_eq!(
        result,
        Scalar::from_raw([
            0x7fff_ffff_8000_0001,
            0xa9de_d201_7fff_2dff,
            0x199c_ec04_04d0_ec02,
            0x39f6_d3a9_94ce_bea4,
        ])
    );
}

fn main() {
    t_modadd();
    t_modmul();
    t_modinv();
}
