//! TPM2-based crypto module for ashura
//! This module provides implementations for cryptographic operations using TPM2 hardware.

use tss_esapi::{
    Context as Tpm2Context, TctiNameConf,
    attributes::ObjectAttributes,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
    },
    structures::{
        EccParameter, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Public,
        PublicBuilder, PublicEccParameters, SymmetricDefinitionObject,
    },
};

fn public_key_opts(object_attributes: ObjectAttributes, ecc_params: PublicEccParameters) -> Public {
    let ecc_unique = EccPoint::new(EccParameter::default(), EccParameter::default());

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(ecc_unique)
        .build()
        .unwrap()
}

fn ecc_params() -> PublicEccParameters {
    PublicEccParameters::builder()
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_ecc_scheme(EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_is_decryption_key(true)
        .build()
        .unwrap()
}

#[derive(Debug)]
pub struct Tpm2Crypt {
    context: Tpm2Context,
}

impl Tpm2Crypt {
    pub fn new(tcti: &TctiNameConf) -> Self {
        // todo: tss bullshit

        println!("Using TCTI: {:?}", tcti);

        let context = Tpm2Context::new(tcti.to_owned()).expect("Failed to create TPM2 Context");

        // println!("TPM2 Context created successfully");
        // println!("{:#?}", context);

        Self { context }
    }

    #[tracing::instrument]
    pub fn gen_srk(&self) {
        let object_attributes = ObjectAttributes::builder()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_decrypt(false)
            .with_user_with_auth(true)
            .build()
            .unwrap();
        println!("Object Attributes for ECC key: {:#?}", object_attributes);

        let ecc_params = ecc_params();
        println!("ECC Parameters: {:#?}", ecc_params);

        let public = public_key_opts(object_attributes, ecc_params);
        println!("Public area for ECC key: {:#?}", public);
    }
}
