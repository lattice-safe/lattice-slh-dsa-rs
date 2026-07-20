//! SLH-DSA parameter sets (FIPS 205).

#[cfg(feature = "serde")]
fn default_name() -> &'static str {
    ""
}

/// Hash function family used by a parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HashFamily {
    Shake,
    Sha2,
}

/// SLH-DSA parameter set.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SlhDsaMode {
    #[cfg_attr(feature = "serde", serde(skip, default = "default_name"))]
    pub name: &'static str,
    pub hash: HashFamily,
    /// Security parameter (hash output length in bytes).
    pub n: usize,
    /// Full height of the hypertree.
    pub full_height: usize,
    /// Number of subtree layers.
    pub d: usize,
    /// FORS tree height.
    pub fors_height: usize,
    /// Number of FORS trees.
    pub fors_trees: usize,
    /// Winternitz parameter.
    pub wots_w: usize,
}

/// Equality compares the numeric parameters only. `name` is excluded because
/// it is a display label and is skipped during serde deserialization, so a
/// round-tripped mode must still compare equal to its source constant.
impl PartialEq for SlhDsaMode {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.n == other.n
            && self.full_height == other.full_height
            && self.d == other.d
            && self.fors_height == other.fors_height
            && self.fors_trees == other.fors_trees
            && self.wots_w == other.wots_w
    }
}

impl Eq for SlhDsaMode {}

impl SlhDsaMode {
    pub const fn wots_logw(&self) -> usize {
        match self.wots_w {
            256 => 8,
            16 => 4,
            _ => 4,
        }
    }

    pub const fn wots_len1(&self) -> usize {
        8 * self.n / self.wots_logw()
    }

    pub const fn wots_len2(&self) -> usize {
        if self.wots_w == 16 {
            if self.n <= 8 {
                2
            } else if self.n <= 136 {
                3
            } else {
                4
            }
        } else if self.n <= 1 {
            1
        } else {
            2
        }
    }

    pub const fn wots_len(&self) -> usize {
        self.wots_len1() + self.wots_len2()
    }

    pub const fn wots_bytes(&self) -> usize {
        self.wots_len() * self.n
    }

    pub const fn tree_height(&self) -> usize {
        self.full_height / self.d
    }

    pub const fn fors_msg_bytes(&self) -> usize {
        (self.fors_height * self.fors_trees + 7) / 8
    }

    pub const fn fors_bytes(&self) -> usize {
        (self.fors_height + 1) * self.fors_trees * self.n
    }

    /// Total signature size in bytes.
    pub const fn sig_bytes(&self) -> usize {
        self.n + self.fors_bytes() + self.d * self.wots_bytes() + self.full_height * self.n
    }

    /// Public key size in bytes.
    pub const fn pk_bytes(&self) -> usize {
        2 * self.n
    }

    /// Secret key size in bytes.
    pub const fn sk_bytes(&self) -> usize {
        2 * self.n + self.pk_bytes()
    }

    /// Seed size (3 * n).
    pub const fn seed_bytes(&self) -> usize {
        3 * self.n
    }

    pub const fn tree_bits(&self) -> usize {
        self.tree_height() * (self.d - 1)
    }

    pub const fn tree_bytes(&self) -> usize {
        (self.tree_bits() + 7) / 8
    }

    pub const fn leaf_bits(&self) -> usize {
        self.tree_height()
    }

    pub const fn leaf_bytes(&self) -> usize {
        (self.leaf_bits() + 7) / 8
    }

    pub const fn dgst_bytes(&self) -> usize {
        self.fors_msg_bytes() + self.tree_bytes() + self.leaf_bytes()
    }
}

// FIPS 205 parameter sets — SHAKE variants
pub const SLH_DSA_SHAKE_128S: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHAKE-128s",
    hash: HashFamily::Shake,
    n: 16,
    full_height: 63,
    d: 7,
    fors_height: 12,
    fors_trees: 14,
    wots_w: 16,
};
pub const SLH_DSA_SHAKE_128F: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHAKE-128f",
    hash: HashFamily::Shake,
    n: 16,
    full_height: 66,
    d: 22,
    fors_height: 6,
    fors_trees: 33,
    wots_w: 16,
};
pub const SLH_DSA_SHAKE_192S: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHAKE-192s",
    hash: HashFamily::Shake,
    n: 24,
    full_height: 63,
    d: 7,
    fors_height: 14,
    fors_trees: 17,
    wots_w: 16,
};
pub const SLH_DSA_SHAKE_192F: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHAKE-192f",
    hash: HashFamily::Shake,
    n: 24,
    full_height: 66,
    d: 22,
    fors_height: 8,
    fors_trees: 33,
    wots_w: 16,
};
pub const SLH_DSA_SHAKE_256S: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHAKE-256s",
    hash: HashFamily::Shake,
    n: 32,
    full_height: 64,
    d: 8,
    fors_height: 14,
    fors_trees: 22,
    wots_w: 16,
};
pub const SLH_DSA_SHAKE_256F: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHAKE-256f",
    hash: HashFamily::Shake,
    n: 32,
    full_height: 68,
    d: 17,
    fors_height: 9,
    fors_trees: 35,
    wots_w: 16,
};

// FIPS 205 parameter sets — SHA-2 variants
pub const SLH_DSA_SHA2_128S: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHA2-128s",
    hash: HashFamily::Sha2,
    n: 16,
    full_height: 63,
    d: 7,
    fors_height: 12,
    fors_trees: 14,
    wots_w: 16,
};
pub const SLH_DSA_SHA2_128F: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHA2-128f",
    hash: HashFamily::Sha2,
    n: 16,
    full_height: 66,
    d: 22,
    fors_height: 6,
    fors_trees: 33,
    wots_w: 16,
};
pub const SLH_DSA_SHA2_192S: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHA2-192s",
    hash: HashFamily::Sha2,
    n: 24,
    full_height: 63,
    d: 7,
    fors_height: 14,
    fors_trees: 17,
    wots_w: 16,
};
pub const SLH_DSA_SHA2_192F: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHA2-192f",
    hash: HashFamily::Sha2,
    n: 24,
    full_height: 66,
    d: 22,
    fors_height: 8,
    fors_trees: 33,
    wots_w: 16,
};
pub const SLH_DSA_SHA2_256S: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHA2-256s",
    hash: HashFamily::Sha2,
    n: 32,
    full_height: 64,
    d: 8,
    fors_height: 14,
    fors_trees: 22,
    wots_w: 16,
};
pub const SLH_DSA_SHA2_256F: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHA2-256f",
    hash: HashFamily::Sha2,
    n: 32,
    full_height: 68,
    d: 17,
    fors_height: 9,
    fors_trees: 35,
    wots_w: 16,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake_128f_sizes() {
        let m = SLH_DSA_SHAKE_128F;
        assert_eq!(m.n, 16);
        assert_eq!(m.pk_bytes(), 32);
        assert_eq!(m.sk_bytes(), 64);
        assert_eq!(m.wots_len(), 35);
        assert_eq!(m.tree_height(), 3);
        assert_eq!(m.sig_bytes(), 17088);
    }

    #[test]
    fn test_shake_256s_sizes() {
        let m = SLH_DSA_SHAKE_256S;
        assert_eq!(m.n, 32);
        assert_eq!(m.pk_bytes(), 64);
        assert_eq!(m.sk_bytes(), 128);
        assert_eq!(m.tree_height(), 8);
    }

    #[test]
    fn test_all_fips205_sig_sizes() {
        // FIPS 205 Table 2.
        let cases = [
            (SLH_DSA_SHAKE_128S, 7856),
            (SLH_DSA_SHAKE_128F, 17088),
            (SLH_DSA_SHAKE_192S, 16224),
            (SLH_DSA_SHAKE_192F, 35664),
            (SLH_DSA_SHAKE_256S, 29792),
            (SLH_DSA_SHAKE_256F, 49856),
            (SLH_DSA_SHA2_128S, 7856),
            (SLH_DSA_SHA2_128F, 17088),
            (SLH_DSA_SHA2_192S, 16224),
            (SLH_DSA_SHA2_192F, 35664),
            (SLH_DSA_SHA2_256S, 29792),
            (SLH_DSA_SHA2_256F, 49856),
        ];
        for (m, sig) in cases {
            assert_eq!(m.sig_bytes(), sig, "{}", m.name);
            assert_eq!(m.seed_bytes(), 3 * m.n, "{}", m.name);
            assert_eq!(
                m.dgst_bytes(),
                m.fors_msg_bytes() + m.tree_bytes() + m.leaf_bytes(),
                "{}",
                m.name
            );
            assert_eq!(m.leaf_bits(), m.tree_height(), "{}", m.name);
        }
    }

    #[test]
    fn test_wots_w256_derived_params() {
        // No FIPS 205 set uses w = 256, but the parameter math must hold.
        let mut m = SLH_DSA_SHAKE_128F;
        m.wots_w = 256;
        assert_eq!(m.wots_logw(), 8);
        assert_eq!(m.wots_len1(), 16);
        assert_eq!(m.wots_len2(), 2);
        assert_eq!(m.wots_len(), 18);

        m.n = 1;
        assert_eq!(m.wots_len2(), 1);
    }

    #[test]
    fn test_wots_w16_len2_branches() {
        let mut m = SLH_DSA_SHAKE_128F;
        assert_eq!(m.wots_len2(), 3); // 8 < n <= 136
        m.n = 8;
        assert_eq!(m.wots_len2(), 2); // n <= 8
        m.n = 200;
        assert_eq!(m.wots_len2(), 4); // n > 136
    }

    #[test]
    fn test_hash_family_eq() {
        assert_eq!(SLH_DSA_SHAKE_128F.hash, HashFamily::Shake);
        assert_eq!(SLH_DSA_SHA2_128F.hash, HashFamily::Sha2);
        assert_ne!(HashFamily::Shake, HashFamily::Sha2);
    }

    #[test]
    fn test_mode_eq_ignores_name() {
        let mut renamed = SLH_DSA_SHAKE_128F;
        renamed.name = "";
        assert_eq!(renamed, SLH_DSA_SHAKE_128F);
        assert_ne!(SLH_DSA_SHAKE_128F, SLH_DSA_SHAKE_128S);
        assert_ne!(SLH_DSA_SHAKE_128F, SLH_DSA_SHA2_128F);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_mode_serde_roundtrip_eq() {
        let json = serde_json::to_string(&SLH_DSA_SHAKE_192F).unwrap();
        let mode: SlhDsaMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, SLH_DSA_SHAKE_192F);
        assert_eq!(mode.sig_bytes(), SLH_DSA_SHAKE_192F.sig_bytes());
    }
}
