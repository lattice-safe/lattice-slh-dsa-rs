use criterion::{criterion_group, criterion_main, Criterion};
use slh_dsa::params::*;
use slh_dsa::sign::{keygen_seed, sign, verify};

fn bench_shake_128f(c: &mut Criterion) {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![42u8; mode.seed_bytes()];
    let (pk, sk) = keygen_seed(mode, &seed);
    let msg = b"benchmark message";
    let sig = sign(&sk, msg, mode);

    c.bench_function("SLH-DSA-SHAKE-128f keygen", |b| {
        b.iter(|| keygen_seed(mode, &seed))
    });

    c.bench_function("SLH-DSA-SHAKE-128f sign", |b| {
        b.iter(|| sign(&sk, msg, mode))
    });

    c.bench_function("SLH-DSA-SHAKE-128f verify", |b| {
        b.iter(|| verify(&pk, &sig, msg, mode))
    });
}

fn bench_shake_128s(c: &mut Criterion) {
    let mode = SLH_DSA_SHAKE_128S;
    let seed = vec![42u8; mode.seed_bytes()];
    let (pk, sk) = keygen_seed(mode, &seed);
    let msg = b"benchmark message";
    let sig = sign(&sk, msg, mode);

    c.bench_function("SLH-DSA-SHAKE-128s keygen", |b| {
        b.iter(|| keygen_seed(mode, &seed))
    });

    c.bench_function("SLH-DSA-SHAKE-128s sign", |b| {
        b.iter(|| sign(&sk, msg, mode))
    });

    c.bench_function("SLH-DSA-SHAKE-128s verify", |b| {
        b.iter(|| verify(&pk, &sig, msg, mode))
    });
}

criterion_group!(
    benches,
    bench_shake_128f,
    bench_shake_128s,
);
criterion_main!(benches);
