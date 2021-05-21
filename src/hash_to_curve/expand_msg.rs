//! This module implements message expansion consistent with the
//! hash-to-curve RFC drafts 7 through 10

use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use digest::{BlockInput, Digest, ExtendableOutputDirty, Update, XofReader};

use crate::generic_array::{
    typenum::{Unsigned, U32},
    ArrayLength, GenericArray,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

const OVERSIZE_DST_SALT: &[u8] = b"H2C-OVERSIZE-DST-";

/// The domain separation tag for a message expansion.
///
/// Implements [section 5.4.3 of `draft-irtf-cfrg-hash-to-curve-11`][dst].
///
/// [dst]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.3
#[derive(Debug)]
enum ExpandMsgDst<'x, L: ArrayLength<u8>> {
    /// DST produced by hashing a very long (> 255 chars) input DST.
    Hashed(GenericArray<u8, L>),
    /// A raw input DST (<= 255 chars).
    Raw(&'x [u8]),
}

impl<'x, L: ArrayLength<u8>> ExpandMsgDst<'x, L> {
    /// Produces a DST for use with `expand_message_xof`.
    pub fn process_xof<H>(dst: &'x [u8]) -> Self
    where
        H: Default + Update + ExtendableOutputDirty,
    {
        if dst.len() > 255 {
            let mut data = GenericArray::<u8, L>::default();
            H::default()
                .chain(OVERSIZE_DST_SALT)
                .chain(&dst)
                .finalize_xof_dirty()
                .read(&mut data);
            Self::Hashed(data)
        } else {
            Self::Raw(dst)
        }
    }

    /// Produces a DST for use with `expand_message_xmd`.
    pub fn process_xmd<H>(dst: &'x [u8]) -> Self
    where
        H: Digest<OutputSize = L>,
    {
        if dst.len() > 255 {
            Self::Hashed(H::new().chain(OVERSIZE_DST_SALT).chain(&dst).finalize())
        } else {
            Self::Raw(dst)
        }
    }

    /// Returns the raw bytes of the DST.
    pub fn data(&'x self) -> &'x [u8] {
        match self {
            Self::Hashed(arr) => &arr[..],
            Self::Raw(buf) => buf,
        }
    }

    /// Returns the length of the DST.
    pub fn len(&'x self) -> usize {
        match self {
            Self::Hashed(_) => L::to_usize(),
            Self::Raw(buf) => buf.len(),
        }
    }
}

/// A trait for message expansion methods supported by hash-to-curve.
pub trait ExpandMessage: for<'x> InitExpandMessage<'x> {
    // This intermediate is likely only necessary until GATs allow
    // associated types with lifetimes.
}

/// Trait for constructing a new message expander.
pub trait InitExpandMessage<'x> {
    /// The state object used during message expansion.
    type Expander: ExpandMessageState<'x>;

    /// Initializes a message expander.
    fn init_expand(message: &[u8], dst: &'x [u8], len_in_bytes: usize) -> Self::Expander;
}

// Automatically derive trait
impl<X: for<'x> InitExpandMessage<'x>> ExpandMessage for X {}

/// Trait for types implementing the `expand_message` interface for `hash_to_field`.
pub trait ExpandMessageState<'x> {
    /// Reads bytes from the generated output.
    fn read_into(&mut self, output: &mut [u8]) -> usize;

    /// Retrieves the number of bytes remaining in the generator.
    fn remain(&self) -> usize;

    #[cfg(feature = "alloc")]
    /// Constructs a `Vec` containing the remaining bytes of the output.
    fn into_vec(mut self) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut result = alloc::vec![0u8; self.remain()];
        self.read_into(&mut result[..]);
        result
    }
}

/// A generator for the output of `expand_message_xof` for a given
/// extendable hash function, message, DST, and output length.
///
/// Implements [section 5.4.2 of `draft-irtf-cfrg-hash-to-curve-11`][expand_message_xof]
/// with `k = 128`.
///
/// [expand_message_xof]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.2
pub struct ExpandMsgXof<H: ExtendableOutputDirty> {
    hash: <H as ExtendableOutputDirty>::Reader,
    remain: usize,
}

impl<H: ExtendableOutputDirty> Debug for ExpandMsgXof<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandMsgXof")
            .field("remain", &self.remain)
            .finish()
    }
}

impl<'x, H> ExpandMessageState<'x> for ExpandMsgXof<H>
where
    H: ExtendableOutputDirty,
{
    fn read_into(&mut self, output: &mut [u8]) -> usize {
        let len = self.remain.min(output.len());
        self.hash.read(&mut output[..len]);
        self.remain -= len;
        len
    }

    fn remain(&self) -> usize {
        self.remain
    }
}

impl<'x, H> InitExpandMessage<'x> for ExpandMsgXof<H>
where
    H: Default + Update + ExtendableOutputDirty,
{
    type Expander = Self;

    fn init_expand(message: &[u8], dst: &[u8], len_in_bytes: usize) -> Self {
        // Use U32 here for k = 128.
        let dst = ExpandMsgDst::<U32>::process_xof::<H>(dst);
        let hash = H::default()
            .chain(message)
            .chain((len_in_bytes as u16).to_be_bytes())
            .chain(dst.data())
            .chain([dst.len() as u8])
            .finalize_xof_dirty();
        Self {
            hash,
            remain: len_in_bytes,
        }
    }
}

/// Constructor for `expand_message_xmd` for a given digest hash function, message, DST,
/// and output length.
///
/// Implements [section 5.4.1 of `draft-irtf-cfrg-hash-to-curve-11`][expand_message_xmd].
///
/// [expand_message_xmd]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1
#[derive(Debug)]
pub struct ExpandMsgXmd<H: Digest>(PhantomData<H>);

/// A generator for the output of `expand_message_xmd` for a given
/// digest hash function, message, DST, and output length.
///
/// Implements [section 5.4.1 of `draft-irtf-cfrg-hash-to-curve-11`][expand_message_xmd].
///
/// [expand_message_xmd]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1
pub struct ExpandMsgXmdState<'x, H: Digest> {
    dst: ExpandMsgDst<'x, H::OutputSize>,
    b_0: GenericArray<u8, H::OutputSize>,
    b_i: GenericArray<u8, H::OutputSize>,
    i: usize,
    b_offs: usize,
    remain: usize,
}

impl<H: Digest> Debug for ExpandMsgXmdState<'_, H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandMsgXmdState")
            .field("remain", &self.remain)
            .finish()
    }
}

impl<'x, H> InitExpandMessage<'x> for ExpandMsgXmd<H>
where
    H: Digest + BlockInput,
{
    type Expander = ExpandMsgXmdState<'x, H>;

    fn init_expand(message: &[u8], dst: &'x [u8], len_in_bytes: usize) -> Self::Expander {
        let hash_size = <H as Digest>::OutputSize::to_usize();
        let ell = (len_in_bytes + hash_size - 1) / hash_size;
        if ell > 255 {
            panic!("Invalid ExpandMsgXmd usage: ell > 255");
        }
        let dst = ExpandMsgDst::process_xmd::<H>(dst);
        let b_0 = H::new()
            .chain(GenericArray::<u8, <H as BlockInput>::BlockSize>::default())
            .chain(message)
            .chain((len_in_bytes as u16).to_be_bytes())
            .chain([0u8])
            .chain(dst.data())
            .chain([dst.len() as u8])
            .finalize();
        // init with b_1
        let b_i = H::new()
            .chain(&b_0)
            .chain([1u8])
            .chain(dst.data())
            .chain([dst.len() as u8])
            .finalize();
        ExpandMsgXmdState {
            dst,
            b_0,
            b_i,
            i: 2,
            b_offs: 0,
            remain: len_in_bytes,
        }
    }
}

impl<'x, H> ExpandMessageState<'x> for ExpandMsgXmdState<'x, H>
where
    H: Digest + BlockInput,
{
    fn read_into(&mut self, output: &mut [u8]) -> usize {
        let read_len = self.remain.min(output.len());
        let mut offs = 0;
        let hash_size = H::OutputSize::to_usize();
        while offs < read_len {
            let b_offs = self.b_offs;
            let mut copy_len = hash_size - b_offs;
            if copy_len > 0 {
                copy_len = copy_len.min(read_len - offs);
                output[offs..(offs + copy_len)]
                    .copy_from_slice(&self.b_i[b_offs..(b_offs + copy_len)]);
                offs += copy_len;
                self.b_offs = b_offs + copy_len;
            } else {
                let mut b_prev_xor = self.b_0.clone();
                for j in 0..hash_size {
                    b_prev_xor[j] ^= self.b_i[j];
                }
                self.b_i = H::new()
                    .chain(b_prev_xor)
                    .chain([self.i as u8])
                    .chain(self.dst.data())
                    .chain([self.dst.len() as u8])
                    .finalize();
                self.b_offs = 0;
                self.i += 1;
            }
        }
        self.remain -= read_len;
        read_len
    }

    fn remain(&self) -> usize {
        self.remain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Sha512};
    use sha3::{Shake128, Shake256};

    #[cfg(feature = "alloc")]
    #[test]
    fn expand_xmd_long_dst() {
        const MESSAGE: &[u8] = b"test expand xmd input message";
        const LONG_DST: &[u8] = b"test expand xmd long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long dst";

        const EXPECT: &[(usize, &str)] = &[
            (10, "417ab5fec8c0afa8492b"),
            (100, "e70f11136df2be4ce806586e187437a23647be319ed4095032c776b81291905cfccd644d9123f91f18a960936956b851390f61f02785b1aa5ba1d192afce2745afe789933f0e1964eedd4e83e060d1004dea7467db044b589eb14c75b6fc75ed3f2759c7"),
            (1000, "dfff931bf2ca85308ae1baf5a3cae59fb9c2559d0ce1cf7232fbcf208938c5fa3f40186e8db05fdba3f1435491a934f466b7cacf0a5264f7cf958b331973bd7a09e04acd7e608f34f31fce54497a3dd16a6480448abb829ce63726cc9ac2ce22972c26808f11c3e0f8aa3a8a4074bd4ed015a1c20619972262a97b432105a6d11a969651ca239447cb2396a12821cc49de691140aaa882182587803333df94a57690048cf4dce7693cce54777fd5f492ac7881865a6ff889428a90be4083257cf236162e907bac6f4ded45ed745b7c986346eb8582b78fabc649d90277a6021df6fee85532d93bd125d8b61dbcae284486a5bc7c27f9e60a9faf536cdd291c63fc5661ae5415b39882ff6f0659ec8dbc524cf24929496c45fd7dd6e2769045868e0f1e9ce132c5d4e9b24ea9a9ef99178684113d4e77466e8bf95b0925b323db9a8d5782e67b4e7dfe5d233e3d1e305373c9d78ccd3d94f96b576cda18dac4df5a41266228d168f9cbb60cc2161976d2599b8532b554f10e0072bc229c8bda69b2a2521cf0fa79792454e76adbd145e962b185284e908ca45d4595deb392bed197de5cfe5dd5b05510454ac37a3fdc52862844a68e9b5a97219b614132d262c7cf51f8ad410419f62b80f3be4caa55d450ba573a0602116f06c1dda86898042c9a8617ae83f36357f3fa4e3ba930efa8a61fcd51b1a218789d423f135610fb1c1d15ca9a07ced8b043984870d3e42cfba6362cf7b2d3bc64690f14d0ad5ebaf9b20b00fe98de4b469a451a82177eff1fd584a74cfd9c0294686ed152987d598df944d5c8bd68c5a977b8dd33f9af706ba72eaaeae6e6d3d69374a4096281c21f8d8a97141c627967cdf9a2c540e2c95be91614fa69e7db12488e0c439a20aab50f21fd114d3679a2b1245115ddbead473ddc1fe4736c7f368c416a409160848a8d450ab2a7f24f00c8b1f2bc75b4553f4fb2e4e61c1da4ec7a112d5b2c1cf8245f875a52e195665eb5d43ca23e35ec306f25c5e0dfc90366b320db4c9ef1c7af86d7e7c142700fdea52a3288bbff36f49b856b8b012a7b313025b1afa08928c0406effb3d8c5f8903611ba6be55cfad7c527efcda87765d9adc8114fc25e91e64b1f13c76cb01f4d0b50e39d83c9ba211188788bb6d7af51087a00daf0c2dc037e0105e0e5fa20aa1da75e86ef479ad67e01c36afe55d4532726810ae3668c17a1c029d312ee06c356e8fdd37eef01b41c5d8d4828ccae0fb7efb2c1d51059c63b311deb480f2e6c1e42cf315942a0bdbe515471412ba47f78fdca81d5e5fcbb3a207a51c94f306dd4551e0743d3e7f9f48c1b758772b3fe09df98bf857dee124c609f570566cc73cf4746defcc6a8c77c9dad4928911e5e712fb5c90fab41791229b6f8b56fa633")
        ];
        for (len, hexpect) in EXPECT {
            let data = ExpandMsgXmd::<Sha256>::init_expand(MESSAGE, LONG_DST, *len).into_vec();
            assert_eq!(&hex::encode(&data), hexpect);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn expand_xof_long_dst() {
        const MESSAGE: &[u8] = b"test expand xof input message";
        const LONG_DST: &[u8] = b"test expand xof long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long long dst";

        const EXPECT: &[(usize, &str)] = &[
            (10, "b00df0c3074566d72091"),
            (100, "d228fba4aef7bdbe1960975d00734fecde2c1366c014588a28a4084c23b10ac97429df7953cbe811d224ec6d7b76aca88e8b00e50a7ced97e2fbd02b5cc652eb0cff3cbbb4dff1569f84576c6ae127bc3649534c8771a004aef6af08ff9e4ec78ebc85f8"),
            (1000, "8cfd6e04761c87233893639fee0d39358531ea81b79ce545a3f87faa39e41d196ddb5d0755d29d761926eed99265a038584e849e3516c5864849312d33180484e8c75213bc4ea582a5cc55f7b7ecbed89feb2c5799abcc4b87d3627cd84939062de8c9f311e543f3c3c7be2c6ac1441d607209da0640ae3173b1715a2ac0d861c063b5b2be0d85af429afb51a89aa38a25603369955af8c420752eb434a195a0096e9b36218dfa1aab5e6a1cfc140d2be2e91050de9588b2bab05c3ac4b43db91b06483159482daf787562aa417eb886ae9b02a47e8081132fed303fc05ce316e13f4c50eaa09618dc52e77f03dec0424bec634377e857fa3c5f3b39a7695472fb4416fe5c3b4fecebd8d601dbc426ae24b95f8b6baa90b66e79cd4447266d3e9924e57efe903d3fa247c070ede4210d3f836fd0d2313e4832f07d0f9fa2fd28d615e325876cdde509ae75c1bc3c5d0be6881aff0e096cadc3f7d4823ac1ace6ca4f79286bd6d44ad95afcc4950eb26c6823297ab8bf2c6ae7203f4e9d2b35920d85fdb89d2d6120f0901afbed8e9c35794dae30bada9648775ba8dda333cce81be6f63b8cc6e2f686115b37eec11db60706a0a0fa534be88435f761b7f3e42cb6953f8bbcf4a3d2e21a8936af0ba0ab3105d3d780dcf7c4d4934512c32dbb142c5f80f1f5af1ef9f84470956eebf9cdf8a7e0037df7061ed56a8cb030f28d79be37bd72c1cb58883debf62a636e7d56fbcba2df7c5343de80ef79f5db1f02d04ad9c8cffa5ba0752bb106aa94cdacce8c8ce39e8021b9658bd55c1fe1fb7172d5af30c93933662e84ac25c1ba0cfa455782b863ea47029bfc4e78660c647cc21f377e9e5d9d8a94fbaf1087bb3b05a772ec756010beb290a786505832a075238e3899d120ae8c40a721b19e80896bad94746fd69b0e34dd937ae19b663dfee2e9f08678923fa92d66d5dc2c4f461f1eff4b7e8daf6542510a0ded177b38307eb6a4a5b5e3d5218ed752721c8b58a39f33df23a51e0b4b35e10fb2297a2a7590e8af6b587184336152c951bcc314f9d64c298b46e1327a65abe15256df6ff44284d850c392c41b350904da0c82d49bcea7324fb3a4cdc4f1f02f4e7b8da92405eb7e7d83e7bb824029912e9955401229516167700b853a57cd57b6f0ed6d80ab7bda91a49dc471e80d870ff6461c20f0cf5ae6df73181d16a47d20849677291a999578d37fc9ce75d69b1ec38d8d516da808faf09c6f470385d200f4553576f144fcf8f979fea3c98e2672a349cc47cc64dc828237901542b690cff6c54e9ee1d08f4d88a6711c150c139122ae702d6ae1121ddd8cc6a5ad5455980ecfce82a7b717be980ddcb530de526ddddf37711045f97c23963a08ab2ccafabb2e7728448b7c69cedda3ef10")
        ];
        for (len, hexpect) in EXPECT {
            let data = ExpandMsgXof::<Shake128>::init_expand(MESSAGE, LONG_DST, *len).into_vec();
            assert_eq!(&hex::encode(&data), hexpect);
        }
    }

    // Except for internal variables, expand_message_xmd and expand_message_xof did not change
    // between draft 7 and draft 8:
    // <https://tools.ietf.org/rfcdiff?difftype=--hwdiff&url2=draft-irtf-cfrg-hash-to-curve-08.txt>
    // These test vectors are consistent between draft 8 and draft 11.

    /// From <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-08#appendix-I.1>
    #[cfg(feature = "alloc")]
    #[test]
    fn expand_message_xmd_works_for_draft8_testvectors_sha256() {
        let dst = b"QUUX-V01-CS02-with-expander";

        let msg = b"";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("f659819a6473c1835b25ea59e3d38914c98b374f0970b7e4c92181df928fca88")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("1c38f7c211ef233367b2420d04798fa4698080a8901021a795a1151775fe4da7")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("8f7e7b66791f0da0dbb5ec7c22ec637f79758c0a48170bfb7c4611bd304ece89")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("72d5aa5ec810370d1f0013c0df2f1d65699494ee2a39f72e1716b1b964e1c642")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("3b8e704fc48336aca4c2a12195b720882f2162a4b7b13a9c350db46f429b771b")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("8bcffd1a3cae24cf9cd7ab85628fd111bb17e3739d3b53f89580d217aa79526f1708354a76a402d3569d6a9d19ef3de4d0b991e4f54b9f20dcde9b95a66824cbdf6c1a963a1913d43fd7ac443a02fc5d9d8d77e2071b86ab114a9f34150954a7531da568a1ea8c760861c0cde2005afc2c114042ee7b5848f5303f0611cf297f")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("fe994ec51bdaa821598047b3121c149b364b178606d5e72bfbb713933acc29c186f316baecf7ea22212f2496ef3f785a27e84a40d8b299cec56032763eceeff4c61bd1fe65ed81decafff4a31d0198619c0aa0c6c51fca15520789925e813dcfd318b542f8799441271f4db9ee3b8092a7a2e8d5b75b73e28fb1ab6b4573c192")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("c9ec7941811b1e19ce98e21db28d22259354d4d0643e301175e2f474e030d32694e9dd5520dde93f3600d8edad94e5c364903088a7228cc9eff685d7eaac50d5a5a8229d083b51de4ccc3733917f4b9535a819b445814890b7029b5de805bf62b33a4dc7e24acdf2c924e9fe50d55a6b832c8c84c7f82474b34e48c6d43867be")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("48e256ddba722053ba462b2b93351fc966026e6d6db493189798181c5f3feea377b5a6f1d8368d7453faef715f9aecb078cd402cbd548c0e179c4ed1e4c7e5b048e0a39d31817b5b24f50db58bb3720fe96ba53db947842120a068816ac05c159bb5266c63658b4f000cbf87b1209a225def8ef1dca917bcda79a1e42acd8069")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("396962db47f749ec3b5042ce2452b619607f27fd3939ece2746a7614fb83a1d097f554df3927b084e55de92c7871430d6b95c2a13896d8a33bc48587b1f66d21b128a1a8240d5b0c26dfe795a1a842a0807bb148b77c2ef82ed4b6c9f7fcb732e7f94466c8b51e52bf378fba044a31f5cb44583a892f5969dcd73b3fa128816e")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );
    }

    /// From <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-08#appendix-I.2>
    #[cfg(feature = "alloc")]
    #[test]
    fn expand_message_xmd_works_for_draft8_testvectors_sha512() {
        let dst = b"QUUX-V01-CS02-with-expander";

        let msg = b"";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("2eaa1f7b5715f4736e6a5dbe288257abf1faa028680c1d938cd62ac699ead642")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("0eeda81f69376c80c0f8986496f22f21124cb3c562cf1dc608d2c13005553b0f")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("2e375fc05e05e80dbf3083796fde2911789d9e8847e1fcebf4ca4b36e239b338")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("c37f9095fe7fe4f01c03c3540c1229e6ac8583b07510085920f62ec66acc0197")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("af57a7f56e9ed2aa88c6eab45c8c6e7638ae02da7c92cc04f6648c874ebd560e")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("0687ce02eba5eb3faf1c3c539d1f04babd3c0f420edae244eeb2253b6c6d6865145c31458e824b4e87ca61c3442dc7c8c9872b0b7250aa33e0668ccebbd2b386de658ca11a1dcceb51368721ae6dcd2d4bc86eaebc4e0d11fa02ad053289c9b28a03da6c942b2e12c14e88dbde3b0ba619d6214f47212b628f3e1b537b66efcf")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("779ae4fd8a92f365e4df96b9fde97b40486bb005c1a2096c86f55f3d92875d89045fbdbc4a0e9f2d3e1e6bcd870b2d7131d868225b6fe72881a81cc5166b5285393f71d2e68bb0ac603479959370d06bdbe5f0d8bfd9af9494d1e4029bd68ab35a561341dd3f866b3ef0c95c1fdfaab384ce24a23427803dda1db0c7d8d5344a")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("f0953d28846a50e9f88b7ae35b643fc43733c9618751b569a73960c655c068db7b9f044ad5a40d49d91c62302eaa26163c12abfa982e2b5d753049e000adf7630ae117aeb1fb9b61fc724431ac68b369e12a9481b4294384c3c890d576a79264787bc8076e7cdabe50c044130e480501046920ff090c1a091c88391502f0fbac")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("64d3e59f0bc3c5e653011c914b419ba8310390a9585311fddb26791d26663bd71971c347e1b5e88ba9274d2445ed9dcf48eea9528d807b7952924159b7c27caa4f25a2ea94df9508e70a7012dfce0e8021b37e59ea21b80aa9af7f1a1f2efa4fbe523c4266ce7d342acaacd438e452c501c131156b4945515e9008d2b155c258")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("01524feea5b22f6509f6b1e805c97df94faf4d821b01aadeebc89e9daaed0733b4544e50852fd3e019d58eaad6d267a134c8bc2c08bc46c10bfeff3ee03110bcd8a0d695d75a34092bd8b677bdd369a13325549abab54f4ac907b712bdd3567f38c4554c51902b735b81f43a7ef6f938c7690d107c052c7e7b795ac635b3200a")
                .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );
    }

    /// From <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-08#appendix-I.3>
    #[cfg(feature = "alloc")]
    #[test]
    fn expand_message_xof_works_for_draft8_testvectors_shake128() {
        let dst = b"QUUX-V01-CS02-with-expander";

        let msg = b"";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("eca3fe8f7f5f1d52d7ed3691c321adc7d2a0fef1f843d221f7002530070746de")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake128>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("c79b8ea0af10fd8871eda98334ea9d54e9e5282be97521678f987718b187bc08")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake128>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("fb6f4af2a83f6276e9d41784f1e29da5e27566167c33e5cf2682c30096878b73")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake128>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("125d05850db915e0683d17d044d87477e6e7b3f70a450dd097761e18d1d1dcdf")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake128>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("beafd026cb942c86f6a2b31bb8e6bf7173fb1b0caf3c21ea4b3b9d05d904fd23")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake128>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("15733b3fb22fac0e0902c220aeea48e5e47d39f36c2cc03eac34367c48f2a3ebbcb3baa8a0cf17ab12fff4defc7ce22aed47188b6c163e828741473bd89cc646a082cb68b8e835b1374ea9a6315d61db0043f4abf506c26386e84668e077c85ebd9d632f4390559b979e70e9e7affbd0ac2a212c03b698efbbe940f2d164732b")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake128>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("4ccafb6d95b91537798d1fbb25b9fbe1a5bbe1683f43a4f6f03ef540b811235317bfc0aefb217faca055e1b8f32dfde9eb102cdc026ed27caa71530e361b3adbb92ccf68da35aed8b9dc7e4e6b5db0666c607a31df05513ddaf4c8ee23b0ee7f395a6e8be32eb13ca97da289f2643616ac30fe9104bb0d3a67a0a525837c2dc6")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake128>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("c8ee0e12736efbc9b47781db9d1e5db9c853684344a6776eb362d75b354f4b74cf60ba1373dc2e22c68efb76a022ed5391f67c77990802018c8cdc7af6d00c86b66a3b3ccad3f18d90f4437a165186f6601cf0bb281ea5d80d1de20fe22bb2e2d8acab0c043e76e3a0f34e0a1e66c9ade4fef9ef3b431130ad6f232babe9fe68")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake128>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("3eebe6721b2ec746629856dc2dd3f03a830dabfefd7e2d1e72aaf2127d6ad17c988b5762f32e6edf61972378a4106dc4b63fa108ad03b793eedf4588f34c4df2a95b30995a464cb3ee31d6dca30adbfc90ffdf5414d7893082c55b269d9ec9cd6d2a715b9c4fad4eb70ed56f878b55a17b5994ef0de5b338675aad35354195cd")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake128>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x80;
        let uniform_bytes =
            hex::decode("858cb4a6a5668a97d0f7039b5d6d574dde18dd2323cf6b203945c66df86477d1f747b46401903b3fa66d1276108ea7187b4411b7499acf4600080ce34ff6d21555c2af16f091adf8b285c8439f2e47fa0553c3a6ef5a4227a13f34406241b7d7fd8853a080bad25ec4804cdfe4fda500e1c872e71b8c61a8e160691894b96058")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake128>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );
    }

    /// From <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-11#appendix-K.4>
    #[cfg(feature = "alloc")]
    #[test]
    fn expand_message_xof_works_for_draft11_testvectors_shake256() {
        let dst = b"QUUX-V01-CS02-with-expander";

        let msg = b"";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("58e90433d81860c47d350b0bb6fb94f98f6b0f9657efd04d410ae743260c096d")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("c7f5e3c044790033707e24f21d971aaa03a760dfda6215bf0c8634da9012c8f8")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("f46930964d5d5006ef992f5878d7c255c9a92aed1032c9b9d4743ec1470a91e8")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("885baaf4841ad28aa853022289cb4841cc6c1bf200c579e8aebb8d005a8ff37f")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x20;
        let uniform_bytes =
            hex::decode("4a9884b31a64772244df05622222db6cb9942034370d2400e39bb853cca727f7")
                .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "4cbc65744a4a26c059472822a4647887abb4a3220d5c1e11\
            55c4180a04c69541d437b77676fc5b6450faa5cb906d88a8fa7e1c\
            6807d0a66f0092cc022812368e75ba41dcb4daab00a17e752d485f\
            5e21f835ac36f05b9d0217c79376045e1360faa4652db9d7752af1\
            ffb76ae14cf6aabd7b08b19032d213415d2cef8cd6b62f",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "c5f366dc668697014a0a90a40ae27c19edcb8500f6ad5d42\
            34fbf4204f64df524a44adaecb42102fffeb7686949aa6785142b2\
            510a419dd29dadf1f2b455688c043f6bc2fd76b101dd8e41cca404\
            2514a6b15d137d958735961e3c32a49e0640ad564d533d20adc203\
            c5befdb1186ca18646b729a5cb4531922d24a17b4389ea",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "34dcc64cee945b94c5e29a9aa6b859b8a9705fe020bf7443\
            eaab4c8269e739904e2703cef64e1823b5c848570db97b28da7869\
            f52c24573d8f759b7181726e186dcff940eea5f70a11ebd14b4c90\
            c3b17805ce91dc3157ce635e9d11fe56d86dfa76a79e84c11e2536\
            53350d2f954922077f2ea6a17104dd0fd963d7fe4568d3",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "b0adc10a4326ae3ddf11c42afb89058625f8812c76b2a0fb\
            17570f7a2acb030e8dd20036d1326984fd0d973197d80fbf461fe1\
            8ef394b9a22e609e61d710df43476ddf3a8ca4d32b737bc265d14a\
            204f32173e447db74bc68938b6a6a08e3e9a31968e5d05a0ca213c\
            977e94cffc9a535b5c5198a6c5892bbce1a35ecc7ab2bd",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "50a0cb335f3102a15f3dfed981b0a5fecb3136112532e129\
            d39369a2a92c32a9b0a0181af9839039c0e98a3b66a0d209fa0191\
            34991055284c3f475c9f7c91169dea57aad442f0c98418d36e50fa\
            d68e8863109dac6d8cfc6c5fa63e8f1c0468af9980066e87b62caa\
            87f4b3feef0dba8ef894f2957105d111439597d3265b1f",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXof::<Shake256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );
    }
}
