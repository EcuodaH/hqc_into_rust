use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hqc::parameters::VEC_N_SIZE_64; 
use hqc::gf2x;

fn bench_vect_mul(c: &mut Criterion) {
    let vec_a = vec![0u64; VEC_N_SIZE_64];  
    let vec_b = vec![0u64; VEC_N_SIZE_64];
    let mut result = vec![0u64; VEC_N_SIZE_64];

    c.bench_function("vect_mul", |bencher| { 
        bencher.iter(|| gf2x::vect_mul(
            black_box(&mut result),
            black_box(&vec_a),
            black_box(&vec_b),
        ))
    });
}

criterion_group!(benches, bench_vect_mul);
criterion_main!(benches);