use std::time::Instant;

use eyre::{eyre, Result};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField, secp256k1_base::Secp256K1Base,
        secp256k1_scalar::Secp256K1Scalar, types::PrimeField,
    },
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::CompressedProofWithPublicInputs,
    },
};
use plonky2_ecdsa::{
    curve::secp256k1::Secp256K1,
    gadgets::{
        biguint::{
            witness_get_biguint_target, witness_set_biguint_target, BigUintTarget,
            CircuitBuilderBiguint,
        },
        curve::AffinePointTarget,
        ecdsa::{verify_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget},
        nonnative::{CircuitBuilderNonNative, NonNativeTarget},
    },
};
use tracing::{event, info, info_span, log, span, Level, warn};

use crate::{MessageHash, PublicKey, Signature};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type Builder = CircuitBuilder<F, D>;
type Proof = CompressedProofWithPublicInputs<F, C, D>;
type Inputs = PartialWitness<GoldilocksField>;

pub struct Circuit {
    inputs: Vec<SignatureInput>,
    data:   CircuitData<F, C, D>,
}

struct FieldInput<F>
where
    F: PrimeField,
{
    pub biguint:    BigUintTarget,
    pub non_native: NonNativeTarget<F>,
}

impl<F: PrimeField> FieldInput<F> {
    pub fn new(builder: &mut Builder, public: bool) -> Self {
        let biguint = builder.add_virtual_biguint_target(Builder::num_nonnative_limbs::<F>());
        if public {
            biguint.limbs.iter().for_each(|&limb| {
                builder.register_public_input(limb.0);
            });
        }
        let non_native = builder.biguint_to_nonnative(&biguint);
        Self {
            biguint,
            non_native,
        }
    }

    pub fn set(&self, witness: &mut Inputs, value: F) {
        witness_set_biguint_target(witness, &self.biguint, &value.to_canonical_biguint());
    }

    pub fn get(&self, witness: &Inputs) -> F {
        let n = witness_get_biguint_target(witness, &self.biguint);
        F::from_biguint(n)
    }
}

struct SignatureInput {
    pub pubkey_x: FieldInput<Secp256K1Base>,
    pub pubkey_y: FieldInput<Secp256K1Base>,
    pub msg:      FieldInput<Secp256K1Scalar>,
    pub sig_r:    FieldInput<Secp256K1Scalar>,
    pub sig_s:    FieldInput<Secp256K1Scalar>,
}

impl SignatureInput {
    pub fn new(builder: &mut Builder) -> Self {
        let span = info_span!("SignatureInput::new");
        let _guard = span.enter();
        builder.push_context(log::Level::Info, "Secp256K1Verifier");

        // Inputs
        builder.push_context(log::Level::Info, "inputs");
        let si = info_span!("inputs").in_scope(|| Self {
            pubkey_x: FieldInput::new(builder, true),
            pubkey_y: FieldInput::new(builder, true),
            msg:      FieldInput::new(builder, true),
            sig_r:    FieldInput::new(builder, false),
            sig_s:    FieldInput::new(builder, false),
        });
        builder.pop_context();

        // Verifier circuit
        builder.push_context(log::Level::Info, "verify_message_circuit");
        info_span!("verify_message_circuit").in_scope(|| {
            let pk = ECDSAPublicKeyTarget::<Secp256K1>(AffinePointTarget {
                x: si.pubkey_x.non_native.clone(),
                y: si.pubkey_y.non_native.clone(),
            });
            let msg = si.msg.non_native.clone();
            let sig = ECDSASignatureTarget::<Secp256K1> {
                r: si.sig_r.non_native.clone(),
                s: si.sig_s.non_native.clone(),
            };
            verify_message_circuit(builder, msg, sig, pk);
        });
        builder.pop_context();

        builder.pop_context();
        si
    }

    pub fn set(&self, witness: &mut Inputs, (pk, msg, sig): (PublicKey, MessageHash, Signature)) {
        self.pubkey_x.set(witness, pk.0.x);
        self.pubkey_y.set(witness, pk.0.y);
        self.msg.set(witness, msg);
        self.sig_r.set(witness, sig.r);
        self.sig_s.set(witness, sig.s);
    }
}

impl Circuit {
    pub fn new(n: usize) -> Circuit {
        let span = info_span!("Circuit::new", n);
        let _guard = span.enter();

        // Configure circuit builder
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Start building circuit
        let span = info_span!("constructing");
        let constructing_guard = span.enter();
        builder.push_context(log::Level::Info, "Circuit");

        // Verifiers
        builder.push_context(log::Level::Info, "Verifiers");
        let inputs = (0..n).map(|_| SignatureInput::new(&mut builder)).collect();
        builder.pop_context();

        // Stop building circuit
        drop(constructing_guard);
        builder.pop_context();

        // Compile circuit
        builder.print_gate_counts(0); // TODO: Add to span
        let data = info_span!("compiling").in_scope(|| builder.build::<C>());

        Self { inputs, data }
    }

    pub fn prove(
        &self,
        input: impl IntoIterator<Item = (PublicKey, MessageHash, Signature)>,
    ) -> Result<Proof> {
        let span = info_span!(
            "proving",
            security_bits = self.data.common.config.security_bits,
            degree = %self.data.common.degree(),
            constraint_degree = %self.data.common.constraint_degree(),
        );
        let _guard = span.enter();

        // Set public inputs
        // TODO: Make sure enough inputs are supplied.
        let pw = span!(Level::INFO, "set_public_inputs", n = self.inputs.len()).in_scope(|| {
            let mut pw = PartialWitness::new();
            for (target, value) in self.inputs.iter().zip(input) {
                target.set(&mut pw, value);
            }
            pw
        });

        // Proof
        let start = Instant::now();
        let proof = {
            let span = span!(Level::INFO, "computing_compressed_proof");
            let _ = span.enter();
            self.data
                .prove(pw)
                .and_then(|proof| proof.compress(&self.data.common))
                .map_err(|e| eyre!(e))?
        };
        let proof_time = start.elapsed();
        let proof_bytes = proof.to_bytes().map_err(|e| eyre!(e))?;
        span.record("proof_size", &proof_bytes.len());
        println!("Batch size: {}", self.inputs.len());
        println!("Proof size: {}", proof_bytes.len());
        println!("Proof time: {:4}.{:09}", proof_time.as_secs(), proof_time.subsec_nanos());

        Ok(proof)
    }

    pub fn verify(&self, proof: Proof) -> Result<()> {
        let span = info_span!("verifying");
        let _guard = span.enter();

        // Uncompress proof
        let proof = proof.decompress(&self.data.common).map_err(|e| eyre!(e))?;

        self.data.verify(proof).map_err(|e| eyre!(e))
    }
}
