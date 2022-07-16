#![doc = include_str!("../Readme.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]

mod circuit;

use self::circuit::Circuit;
use clap::Parser;
use eyre::Result;
use tracing::instrument;

#[derive(Clone, Debug, Parser)]
pub struct Options {}

#[instrument]
pub async fn main(options: Options) -> Result<()> {
    let circuit = Circuit::new(5);

    let proof = circuit.prove([])?;

    circuit.verify(proof)?;

    Ok(())
}

#[cfg(feature = "bench")]
pub mod bench {
    use criterion::{black_box, BatchSize, Criterion};
    use proptest::{
        strategy::{Strategy, ValueTree},
        test_runner::TestRunner,
    };

    pub fn group(criterion: &mut Criterion) {
        bench_example_proptest(criterion);
    }

    /// Example proptest benchmark
    /// Uses proptest to randomize the benchmark input
    fn bench_example_proptest(criterion: &mut Criterion) {
        let input = (0..5, 0..5);
        let mut runner = TestRunner::deterministic();
        // Note: benchmarks need to have proper identifiers as names for
        // the CI to pick them up correctly.
        criterion.bench_function("example_proptest", move |bencher| {
            bencher.iter_batched(
                || input.new_tree(&mut runner).unwrap().current(),
                |(a, b)| {
                    // Benchmark number addition
                    black_box(a + b)
                },
                BatchSize::LargeInput,
            );
        });
    }
}
