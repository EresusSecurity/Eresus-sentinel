// benches/generation.rs — Criterion benchmarks for pickle generation + scanning

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sentinel_pickle::generator::Generator;
use sentinel_pickle::policy::ScanPolicy;
use sentinel_pickle::scanner::scan_data;

fn bench_single_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_generation");

    let configs = vec![
        ("small_4-16", 4, 16),
        ("medium_16-64", 16, 64),
        ("large_64-256", 64, 256),
        ("xlarge_256-512", 256, 512),
    ];

    for (name, min, max) in configs {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("opcodes", name),
            &(min, max),
            |b, &(min, max)| {
                b.iter(|| {
                    let mut gen = Generator::new(4).min_opcodes(min).max_opcodes(max);
                    black_box(gen.generate(42).unwrap())
                });
            },
        );
    }

    group.finish();
}

fn bench_protocol_versions(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol_versions");

    for version in 0..=5u8 {
        group.bench_with_input(
            BenchmarkId::from_parameter(version),
            &version,
            |b, &version| {
                b.iter(|| {
                    let mut gen = Generator::new(version).min_opcodes(8).max_opcodes(64);
                    black_box(gen.generate(42).unwrap())
                });
            },
        );
    }

    group.finish();
}

fn bench_batch_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_generation");

    let batch_sizes = vec![10, 100, 1000];

    for size in batch_sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                for i in 0..size {
                    let mut gen = Generator::new(4).min_opcodes(8).max_opcodes(64);
                    black_box(gen.generate(42 + i as u64).unwrap());
                }
            });
        });
    }

    group.finish();
}

fn bench_scan_generated(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_generated");

    let policy = ScanPolicy::new(false);
    let strict_policy = ScanPolicy::new(true);

    let configs = vec![
        ("small", 4, 16),
        ("medium", 16, 64),
        ("large", 64, 256),
    ];

    for (name, min, max) in configs {
        let mut gen = Generator::new(4).min_opcodes(min).max_opcodes(max);
        let pickle = gen.generate(42).unwrap();

        group.throughput(Throughput::Bytes(pickle.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("non_strict", name),
            &pickle,
            |b, pickle| {
                b.iter(|| black_box(scan_data(pickle, &policy)));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("strict", name),
            &pickle,
            |b, pickle| {
                b.iter(|| black_box(scan_data(pickle, &strict_policy)));
            },
        );
    }

    group.finish();
}

fn bench_deterministic(c: &mut Criterion) {
    let mut group = c.benchmark_group("deterministic");

    group.bench_function("with_seed", |b| {
        b.iter(|| {
            let mut gen = Generator::new(4).min_opcodes(8).max_opcodes(64);
            black_box(gen.generate(42).unwrap())
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_generation,
    bench_protocol_versions,
    bench_batch_generation,
    bench_scan_generated,
    bench_deterministic
);
criterion_main!(benches);
