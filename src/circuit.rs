use eyre::{eyre, Result};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    iop::{
        target::Target,
        witness::{PartialWitness, Witness},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, KeccakGoldilocksConfig, PoseidonGoldilocksConfig},
        proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs},
    },
};
use tracing::{info, info_span, log, span, Level};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type Builder = CircuitBuilder<F, D>;
type Proof = CompressedProofWithPublicInputs<F, C, D>;

pub struct Circuit {
    inputs:  Vec<Target>,
    outputs: Vec<Target>,
    data:    CircuitData<F, C, D>,
}

impl Circuit {
    pub fn new(n: usize) -> Circuit {
        let span = info_span!("Building circuit for for secp256k1 verifications", n);
        let _guard = span.enter();

        // Configure circuit builder
        let config = CircuitConfig {
            ..CircuitConfig::default()
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Start building circuit
        let span = info_span!("Constructing circuit");
        let constructing_guard = span.enter();
        builder.push_context(log::Level::Info, "Circuit");

        // Inputs
        builder.push_context(log::Level::Info, "Inputs");
        let inputs = builder.add_virtual_targets(0);
        inputs
            .iter()
            .for_each(|target| builder.register_public_input(*target));
        builder.pop_context();

        // Circuit
        let outputs = Vec::new();

        // Stop building circuit
        drop(constructing_guard);
        builder.pop_context();

        // Compile circuit
        builder.print_gate_counts(0); // TODO: Add to span
        let data = info_span!("Compiling circuit").in_scope(|| builder.build::<C>());

        Self {
            inputs,
            outputs,
            data,
        }
    }

    pub fn prove(&self, input: impl IntoIterator<Item = GoldilocksField>) -> Result<Proof> {
        let span = info_span!(
            "Proving circuit",
            security_bits = self.data.common.config.security_bits,
            degree = %self.data.common.degree(),
            constraint_degree = %self.data.common.constraint_degree(),
        );
        let _guard = span.enter();

        // Set public inputs
        let pw = span!(Level::INFO, "Set public inputs", n = self.inputs.len()).in_scope(|| {
            let mut pw = PartialWitness::new();
            for (&target, value) in self.inputs.iter().zip(input) {
                pw.set_target(target, value);
            }
            pw
        });

        // Proof
        let proof = {
            let span = span!(Level::INFO, "Computing compressed proof");
            let _ = span.enter();
            self.data
                .prove(pw)
                .and_then(|proof| proof.compress(&self.data.common))
                .map_err(|e| eyre!(e))?
        };
        let proof_bytes = proof.to_bytes().map_err(|e| eyre!(e))?;
        span.record("proof_size", &proof_bytes.len());

        Ok(proof)
    }

    pub fn verify(&self, proof: Proof) -> Result<()> {
        let span = info_span!("Verifying compressed proof");
        let _guard = span.enter();

        // Uncompress proof
        let proof = proof.decompress(&self.data.common).map_err(|e| eyre!(e))?;

        self.data.verify(proof).map_err(|e| eyre!(e))
    }
}
