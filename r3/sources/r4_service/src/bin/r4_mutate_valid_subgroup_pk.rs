use ark_bls12_381::{Bls12_381, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::{env, fs, io::Cursor, path::PathBuf};

fn main() {
    let args = env::args().collect::<Vec<_>>();
    assert_eq!(args.len(), 3, "usage: r4_mutate_valid_subgroup_pk INPUT_PK OUTPUT_PK");
    let input = fs::read(&args[1]).unwrap();
    let mut cursor = Cursor::new(&input);
    let mut pk = ProvingKey::<Bls12_381>::deserialize_compressed(&mut cursor).unwrap();
    assert_eq!(cursor.position() as usize, input.len());
    assert!(!pk.a_query.is_empty());
    pk.a_query[0] = (pk.a_query[0].into_group() + G1Projective::generator()).into_affine();
    let mut output = Vec::new();
    pk.serialize_compressed(&mut output).unwrap();
    fs::write(PathBuf::from(&args[2]), output).unwrap();
}
