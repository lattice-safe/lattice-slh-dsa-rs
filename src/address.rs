//! ADRS (Address) structure for SLH-DSA.
//!
//! The address is a 32-byte array with fields at specific byte offsets.
//! SHAKE and SHA-2 variants use different layouts.

use crate::params::{HashFamily, SlhDsaMode};

/// Address type constants.
pub const ADDR_TYPE_WOTS: u8 = 0;
pub const ADDR_TYPE_WOTSPK: u8 = 1;
pub const ADDR_TYPE_HASHTREE: u8 = 2;
pub const ADDR_TYPE_FORSTREE: u8 = 3;
pub const ADDR_TYPE_FORSPK: u8 = 4;
pub const ADDR_TYPE_WOTSPRF: u8 = 5;
pub const ADDR_TYPE_FORSPRF: u8 = 6;

pub const ADDR_BYTES: usize = 32;

/// ADRS is a 32-byte array.
pub type Addr = [u8; ADDR_BYTES];

/// Byte offsets for SHAKE address layout.
mod shake_offsets {
    pub const LAYER: usize = 3;
    pub const TREE: usize = 8;
    pub const TYPE: usize = 19;
    pub const KP_ADDR: usize = 20;
    pub const CHAIN_ADDR: usize = 27;
    pub const HASH_ADDR: usize = 31;
    pub const TREE_HGT: usize = 27;
    pub const TREE_INDEX: usize = 28;
}

/// Byte offsets for SHA-2 address layout.
mod sha2_offsets {
    pub const LAYER: usize = 0;
    pub const TREE: usize = 1;
    pub const TYPE: usize = 9;
    pub const KP_ADDR: usize = 10;
    pub const CHAIN_ADDR: usize = 17;
    pub const HASH_ADDR: usize = 21;
    pub const TREE_HGT: usize = 17;
    pub const TREE_INDEX: usize = 18;
}

/// Get the byte offsets for the given hash family.
fn offsets(mode: &SlhDsaMode) -> (usize, usize, usize, usize, usize, usize, usize, usize) {
    match mode.hash {
        HashFamily::Shake => (
            shake_offsets::LAYER,
            shake_offsets::TREE,
            shake_offsets::TYPE,
            shake_offsets::KP_ADDR,
            shake_offsets::CHAIN_ADDR,
            shake_offsets::HASH_ADDR,
            shake_offsets::TREE_HGT,
            shake_offsets::TREE_INDEX,
        ),
        HashFamily::Sha2 => (
            sha2_offsets::LAYER,
            sha2_offsets::TREE,
            sha2_offsets::TYPE,
            sha2_offsets::KP_ADDR,
            sha2_offsets::CHAIN_ADDR,
            sha2_offsets::HASH_ADDR,
            sha2_offsets::TREE_HGT,
            sha2_offsets::TREE_INDEX,
        ),
    }
}

pub fn set_layer_addr(addr: &mut Addr, layer: u32, mode: &SlhDsaMode) {
    let (off_layer, ..) = offsets(mode);
    addr[off_layer] = layer as u8;
}

pub fn set_tree_addr(addr: &mut Addr, tree: u64, mode: &SlhDsaMode) {
    let (_, off_tree, ..) = offsets(mode);
    let bytes = tree.to_be_bytes();
    addr[off_tree..off_tree + 8].copy_from_slice(&bytes);
}

pub fn set_type(addr: &mut Addr, typ: u8, mode: &SlhDsaMode) {
    let (_, _, off_type, ..) = offsets(mode);
    addr[off_type] = typ;
    // NOTE: C reference does NOT clear other fields when setting type.
    // Callers are responsible for setting/clearing fields as needed.
}

pub fn copy_subtree_addr(out: &mut Addr, src: &Addr, mode: &SlhDsaMode) {
    let (_, off_tree, ..) = offsets(mode);
    // Copy from start through tree (tree is 8 bytes starting at off_tree)
    let end = off_tree + 8;
    out[..end].copy_from_slice(&src[..end]);
}

pub fn set_keypair_addr(addr: &mut Addr, keypair: u32, mode: &SlhDsaMode) {
    let (_, _, _, off_kp, ..) = offsets(mode);
    addr[off_kp..off_kp + 4].copy_from_slice(&keypair.to_be_bytes());
}

pub fn copy_keypair_addr(out: &mut Addr, src: &Addr, mode: &SlhDsaMode) {
    let (_, off_tree, _, off_kp, ..) = offsets(mode);
    let end = off_tree + 8;
    out[..end].copy_from_slice(&src[..end]);
    out[off_kp..off_kp + 4].copy_from_slice(&src[off_kp..off_kp + 4]);
}

pub fn set_chain_addr(addr: &mut Addr, chain: u32, mode: &SlhDsaMode) {
    debug_assert!(chain <= 255, "chain address overflow: {chain}");
    let (_, _, _, _, off_chain, ..) = offsets(mode);
    addr[off_chain] = chain as u8;
}

pub fn set_hash_addr(addr: &mut Addr, hash: u32, mode: &SlhDsaMode) {
    debug_assert!(hash <= 255, "hash address overflow: {hash}");
    let (_, _, _, _, _, off_hash, ..) = offsets(mode);
    addr[off_hash] = hash as u8;
}

pub fn set_tree_height(addr: &mut Addr, height: u32, mode: &SlhDsaMode) {
    let (_, _, _, _, _, _, off_hgt, _) = offsets(mode);
    addr[off_hgt] = height as u8;
}

pub fn set_tree_index(addr: &mut Addr, index: u32, mode: &SlhDsaMode) {
    let (_, _, _, _, _, _, _, off_idx) = offsets(mode);
    addr[off_idx..off_idx + 4].copy_from_slice(&index.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{SLH_DSA_SHA2_128F, SLH_DSA_SHAKE_128F};

    #[test]
    fn test_shake_layout() {
        let mode = SLH_DSA_SHAKE_128F;
        let mut addr: Addr = [0; ADDR_BYTES];

        set_layer_addr(&mut addr, 5, &mode);
        assert_eq!(addr[3], 5);

        set_tree_addr(&mut addr, 0x0102030405060708, &mode);
        assert_eq!(&addr[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);

        set_type(&mut addr, ADDR_TYPE_FORSTREE, &mode);
        assert_eq!(addr[19], ADDR_TYPE_FORSTREE);

        set_keypair_addr(&mut addr, 0xAABB, &mode);
        assert_eq!(&addr[20..24], &[0, 0, 0xAA, 0xBB]);

        set_chain_addr(&mut addr, 7, &mode);
        assert_eq!(addr[27], 7);

        set_hash_addr(&mut addr, 9, &mode);
        assert_eq!(addr[31], 9);

        set_tree_height(&mut addr, 4, &mode);
        assert_eq!(addr[27], 4);

        set_tree_index(&mut addr, 0x01020304, &mode);
        assert_eq!(&addr[28..32], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_sha2_layout() {
        let mode = SLH_DSA_SHA2_128F;
        let mut addr: Addr = [0; ADDR_BYTES];

        set_layer_addr(&mut addr, 5, &mode);
        assert_eq!(addr[0], 5);

        set_tree_addr(&mut addr, 0x0102030405060708, &mode);
        assert_eq!(&addr[1..9], &[1, 2, 3, 4, 5, 6, 7, 8]);

        set_type(&mut addr, ADDR_TYPE_WOTSPK, &mode);
        assert_eq!(addr[9], ADDR_TYPE_WOTSPK);

        set_keypair_addr(&mut addr, 0xAABB, &mode);
        assert_eq!(&addr[10..14], &[0, 0, 0xAA, 0xBB]);

        set_chain_addr(&mut addr, 7, &mode);
        assert_eq!(addr[17], 7);

        set_hash_addr(&mut addr, 9, &mode);
        assert_eq!(addr[21], 9);

        set_tree_height(&mut addr, 4, &mode);
        assert_eq!(addr[17], 4);

        set_tree_index(&mut addr, 0x01020304, &mode);
        assert_eq!(&addr[18..22], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_copy_subtree_and_keypair_addr() {
        for mode in [SLH_DSA_SHAKE_128F, SLH_DSA_SHA2_128F] {
            let mut src: Addr = [0; ADDR_BYTES];
            set_layer_addr(&mut src, 2, &mode);
            set_tree_addr(&mut src, 0xDEADBEEF, &mode);
            set_type(&mut src, ADDR_TYPE_WOTS, &mode);
            set_keypair_addr(&mut src, 0x1234, &mode);

            // copy_subtree_addr copies layer + tree but not type/keypair.
            let mut sub: Addr = [0; ADDR_BYTES];
            copy_subtree_addr(&mut sub, &src, &mode);
            let mut expect_sub: Addr = [0; ADDR_BYTES];
            set_layer_addr(&mut expect_sub, 2, &mode);
            set_tree_addr(&mut expect_sub, 0xDEADBEEF, &mode);
            assert_eq!(sub, expect_sub, "{}", mode.name);

            // copy_keypair_addr additionally copies the keypair field.
            let mut kp: Addr = [0; ADDR_BYTES];
            copy_keypair_addr(&mut kp, &src, &mode);
            let mut expect_kp = expect_sub;
            set_keypair_addr(&mut expect_kp, 0x1234, &mode);
            assert_eq!(kp, expect_kp, "{}", mode.name);
        }
    }
}
