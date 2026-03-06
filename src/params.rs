//! SLH-DSA parameter sets (FIPS 205).

/// Hash function family used by a parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFamily {
    Shake,
    Sha2,
}

/// SLH-DSA parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlhDsaMode {
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
            if self.n <= 8 { 2 }
            else if self.n <= 136 { 3 }
            else { 4 }
        } else if self.n <= 1 { 1 } else { 2 }
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
        self.n + self.fors_bytes() + self.d * self.wots_bytes()
            + self.full_height * self.n
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
    name: "SLH-DSA-SHAKE-128s", hash: HashFamily::Shake,
    n: 16, full_height: 63, d: 7, fors_height: 12, fors_trees: 14, wots_w: 16,
};
pub const SLH_DSA_SHAKE_128F: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHAKE-128f", hash: HashFamily::Shake,
    n: 16, full_height: 66, d: 22, fors_height: 6, fors_trees: 33, wots_w: 16,
};
pub const SLH_DSA_SHAKE_192S: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHAKE-192s", hash: HashFamily::Shake,
    n: 24, full_height: 63, d: 7, fors_height: 14, fors_trees: 17, wots_w: 16,
};
pub const SLH_DSA_SHAKE_192F: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHAKE-192f", hash: HashFamily::Shake,
    n: 24, full_height: 66, d: 22, fors_height: 8, fors_trees: 33, wots_w: 16,
};
pub const SLH_DSA_SHAKE_256S: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHAKE-256s", hash: HashFamily::Shake,
    n: 32, full_height: 64, d: 8, fors_height: 14, fors_trees: 22, wots_w: 16,
};
pub const SLH_DSA_SHAKE_256F: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHAKE-256f", hash: HashFamily::Shake,
    n: 32, full_height: 68, d: 17, fors_height: 9, fors_trees: 35, wots_w: 16,
};

// FIPS 205 parameter sets — SHA-2 variants
pub const SLH_DSA_SHA2_128S: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHA2-128s", hash: HashFamily::Sha2,
    n: 16, full_height: 63, d: 7, fors_height: 12, fors_trees: 14, wots_w: 16,
};
pub const SLH_DSA_SHA2_128F: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHA2-128f", hash: HashFamily::Sha2,
    n: 16, full_height: 66, d: 22, fors_height: 6, fors_trees: 33, wots_w: 16,
};
pub const SLH_DSA_SHA2_192S: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHA2-192s", hash: HashFamily::Sha2,
    n: 24, full_height: 63, d: 7, fors_height: 14, fors_trees: 17, wots_w: 16,
};
pub const SLH_DSA_SHA2_192F: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHA2-192f", hash: HashFamily::Sha2,
    n: 24, full_height: 66, d: 22, fors_height: 8, fors_trees: 33, wots_w: 16,
};
pub const SLH_DSA_SHA2_256S: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHA2-256s", hash: HashFamily::Sha2,
    n: 32, full_height: 64, d: 8, fors_height: 14, fors_trees: 22, wots_w: 16,
};
pub const SLH_DSA_SHA2_256F: SlhDsaMode = SlhDsaMode {
    name: "SLH-DSA-SHA2-256f", hash: HashFamily::Sha2,
    n: 32, full_height: 68, d: 17, fors_height: 9, fors_trees: 35, wots_w: 16,
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
}
