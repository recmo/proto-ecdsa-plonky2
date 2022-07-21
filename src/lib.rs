#![doc = include_str!("../Readme.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]

mod circuit;

use std::iter::repeat_with;

use self::circuit::Circuit;
use clap::Parser;
use eyre::Result;
use plonky2::field::types::Field;
use plonky2_ecdsa::curve::{
    curve_types::Curve as TCurve,
    ecdsa::{sign_message, verify_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
    secp256k1::Secp256K1,
};
use tracing::instrument;

#[derive(Clone, Debug, Parser)]
pub struct Options {
    /// The number of signatures in the batch.
    #[clap(long, default_value = "4")]
    pub size: usize,
}

type Curve = Secp256K1;
type PublicKey = ECDSAPublicKey<Curve>;
type MessageHash = <Curve as TCurve>::ScalarField;
type Signature = ECDSASignature<Curve>;

fn test_signature() -> (PublicKey, MessageHash, Signature) {
    type Field = <Curve as TCurve>::ScalarField;
    let secret_key = ECDSASecretKey(Field::rand());
    let public_key = secret_key.to_public();
    let message_hash = MessageHash::rand();
    let signature = sign_message(message_hash, secret_key);
    assert!(verify_message(message_hash, signature, public_key));
    (public_key, message_hash, signature)
}

#[allow(clippy::missing_errors_doc)]
#[allow(clippy::unused_async)]
pub async fn main(options: Options) -> Result<()> {
    let n = options.size;
    let circuit = Circuit::new(n);
    let input = repeat_with(test_signature).take(n);
    let proof = circuit.prove(input)?;
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
