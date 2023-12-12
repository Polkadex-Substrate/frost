use crate as frost;
use crate::{hash_to_scalar, params_for_ecrecover};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::thread_rng;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{FieldBytes, Scalar, U256};
use k256::elliptic_curve::generic_array::GenericArray;
use k256::elliptic_curve::hash2curve::FromOkm;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::scalar::FromUintUnchecked;

fn ecrecover(m: [u8; 32], v: u8, r: [u8; 32], s: [u8; 32]) -> [u8; 20] {
    let message = Message::from_digest(m);
    let recovery_id = RecoveryId::from_i32(v as i32).unwrap();
    let signature = RecoverableSignature::from_compact(&[r, s].concat(), recovery_id).unwrap();
    let public_key = signature.recover(&message).unwrap();

    let pub_key_bytes = &public_key.serialize_uncompressed()[1..];
    println!("Recovered Public key: {:?}",hex::encode(pub_key_bytes));
    let hash = Keccak256::digest(pub_key_bytes);
    // println!("Pub key hash: {:?}",hex::encode(hash.to_vec()));
    hash[12..32]
        .try_into()
        .unwrap()
}

fn address(uncompressed_pubk: &[u8;64]) -> [u8; 20] {
    Keccak256::digest(uncompressed_pubk)[12..32]
        .try_into()
        .unwrap()
}

#[test]
pub fn test_ecrecover() {
    let secp = Secp256k1::new();
    let secret_key: SecretKey = SecretKey::from_slice(&[1; 32]).unwrap();
    let public_key = secret_key.public_key(&secp);
    let msg_hash = Message::from_digest(Keccak256::digest(&[1, 2, 3]).to_vec().try_into().unwrap());
    let signature = secret_key.sign_ecdsa(msg_hash);
    signature.verify(&msg_hash, &public_key).unwrap();

    let encoded_sig = signature.serialize_compact();
    let R: [u8;32] = encoded_sig[0..32].try_into().unwrap();
    let S: [u8;32] = encoded_sig[32..64].try_into().unwrap();

    println!("msg: {:?}",hex::encode(msg_hash.as_ref()));
    println!("R: {:?}",hex::encode(R.as_slice()));
    println!("S: {:?}",hex::encode(S.as_slice()));

    let recovered_address = ecrecover(msg_hash.as_ref().clone(), 1, R, S);
    println!("recoverd: {:?}",hex::encode(recovered_address));
    println!("Public key: {:?}",hex::encode(public_key.serialize_uncompressed()));
    let expected_address: [u8; 20] =
        Keccak256::digest(public_key.serialize_uncompressed()[1..].as_ref())[12..32]
            .try_into()
            .unwrap();
    assert_eq!(recovered_address, expected_address);
}

#[test]
pub fn test_ethereum() {
    let mut rng = thread_rng();
    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();
    // ANCHOR_END: tkg_gen

    // Verifies the secret shares from the dealer and store them in a BTreeMap.
    // In practice, the KeyPackages must be sent to its respective participants
    // through a confidential and authenticated channel.
    let mut key_packages: BTreeMap<_, _> = BTreeMap::new();

    for (identifier, secret_share) in shares {
        // ANCHOR: tkg_verify
        let key_package = frost::keys::KeyPackage::try_from(secret_share).unwrap();
        // ANCHOR_END: tkg_verify
        key_packages.insert(identifier, key_package);
    }
    let group_publickey = key_packages
        .values()
        .last()
        .unwrap()
        .verifying_key()
        .clone();
    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_index in 1..(min_signers as u16 + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let key_package = &key_packages[&participant_identifier];
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _threshold_.
        // ANCHOR: round1_commit
        let (nonces, commitments) = frost::round1::commit(
            key_packages[&participant_identifier].signing_share(),
            &mut rng,
        );
        // ANCHOR_END: round1_commit
        // In practice, the nonces must be kept by the participant to use in the
        // next round, while the commitment must be sent to the coordinator
        // (or to every other participant if there is no coordinator) using
        // an authenticated channel.
        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares = BTreeMap::new();
    // ANCHOR: round2_package
    let message = [1u8; 32];
    // In practice, the SigningPackage must be sent to all participants
    // involved in the current signing (at least min_signers participants),
    // using an authenticate channel (and confidential if the message is secret).
    let signing_package = frost::SigningPackage::new(commitments_map, &message);
    // ANCHOR_END: round2_package

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    // In practice, each iteration of this loop will be executed by its respective participant.
    for participant_identifier in nonces_map.keys() {
        let key_package = &key_packages[participant_identifier];

        let nonces = &nonces_map[participant_identifier];

        // Each participant generates their signature share.
        // ANCHOR: round2_sign
        let signature_share = frost::round2::sign(&signing_package, nonces, key_package).unwrap();
        // ANCHOR_END: round2_sign

        // In practice, the signature share must be sent to the Coordinator
        // using an authenticated channel.
        signature_shares.insert(*participant_identifier, signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    // ANCHOR: aggregate
    let group_signature =
        frost::aggregate(&signing_package, &signature_shares, &pubkey_package).unwrap();

    let (m, v, r, s) = params_for_ecrecover(&group_signature, &group_publickey, &message);

    println!("m: {:?}", hex::encode(m));
    println!("v: {:?}", v);
    println!("r: {:?}", hex::encode(r));
    println!("s: {:?}", hex::encode(s));


    const ORDER_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

    /// Order of the secp256k1 elliptic curve.
    // const ORDER: U256 = U256::from_be_hex(ORDER_HEX);
    // let Q: Scalar = Scalar::from_uint_unchecked(ORDER);
    // let HALF_Q = (Q >> 1) + Scalar::ONE;
    let mut Px = Scalar::from_repr(group_publickey.to_element().to_affine().x()).unwrap();
    // if Px >= HALF_Q {
    //     Px = Px.negate();
    // }
    // assert!(Px < HALF_Q);
    let mut signature = group_signature.z();
    // if signature >= Q {
    //     signature = signature.negate();
    // }
    // assert!(signature < Q);
    println!("Inputs for Chainlink contract");
    // uint256 signingPubKeyX,
    // println!("signingPubKeyX: {:?}",hex::encode(Px.to_bytes().as_slice()));
    // //     uint8 pubKeyYParity,
    // println!("pubKeyYParity: {:?}",v);
    // //     uint256 signature,
    // println!("signature: {:?}",hex::encode(signature.to_bytes().as_slice()));
    // //     uint256 msgHash,
    // println!("msgHash: {:?}",hex::encode(message));
    //     address nonceTimesGeneratorAddress
    // println!("R: {:?}",hex::encode(group_signature.R().to_encoded_point(false).as_ref()[1..].as_ref()));
    // /// Do this section in solidity
    // /// e = H(address(R) || m)
    let R = group_signature.R().to_encoded_point(false);
    // println!("Len of R: {:?}",R.len());
    let address = address(R.as_ref()[1..].try_into().unwrap());
    println!("nonceTimesGeneratorAddress: {:?}", hex::encode(address));
    let mut e_preimage = Vec::new();
    e_preimage.extend_from_slice(address.as_slice());
    e_preimage.extend_from_slice(message.as_slice());
    let e = Keccak256::digest(e_preimage).to_vec();

    let address_q = ecrecover(m, v, r, s);
    println!("Recovered address: {:?}",hex::encode(address_q));
    let mut preimage = Vec::new();
    preimage.extend_from_slice(address_q.as_ref());
    preimage.extend_from_slice(message.as_ref());

    let e_ = Keccak256::digest(preimage.as_slice()).to_vec();
    assert_eq!(e, e_);
    println!("E: {:?}", e);
    println!("E': {:?}", e_);
}

pub fn chainlink_verify(signingPubKeyX: Scalar,
                        parity: u8,
                        signature: Scalar,
                        msgHash: [u8;20],
                        nonceGeneratorAddress: [u8;20]
){
    let mut msg_challenge_preimage = Vec::new();
    msg_challenge_preimage.extend_from_slice(nonceGeneratorAddress.as_slice());
    msg_challenge_preimage.extend_from_slice(msgHash.as_slice());

    let msg_challenge: [u8;20] = Keccak256::digest(msg_challenge_preimage).as_slice().try_into().unwrap();



}
