use std::{
    string::{String, ToString},
    fs::File,
    io::{BufReader, BufRead},
    vec::Vec,
};

use sha3::digest::Update;
use serde::{Serialize, Deserialize};

use super::{
    config::{Dim, Config},
    kem::{KeySeed, key_pair, encapsulate, decapsulate},
};

#[derive(Serialize, Deserialize)]
struct Vector<const DIM: usize> {
    main: String,
    reject: String,
    pk: String,
    sk: String,
    e_seed: String,
    ct: String,
    ss: String,
}

#[test]
fn test_2() {
    test::<2>()
}

#[test]
fn test_3() {
    test::<3>()
}

#[test]
fn test_4() {
    test::<4>()
}

fn test<const DIM: usize>()
where
    Dim<DIM>: Config<32>,
{
    Vector::<DIM>::load_and_check(&format!("target/test_vectors{}.txt", 256 * DIM), 10_000);
}

impl<const DIM: usize> Vector<DIM>
where
    Dim<DIM>: Config<32>,
{
    fn load_and_check(txt: &str, limit: usize) {
        let file = File::open(txt).unwrap_or_else(|_| {
            panic!(
                "test vector file `target/test_vectors{}.txt` is missing",
                256 * DIM
            )
        });
        let mut lines = BufReader::new(file)
            .lines()
            .filter_map(Result::ok)
            .take_while(|a| !a.is_empty());
        let mut i = 0;
        while i < limit {
            if let Some(main) = lines.next() {
                let vec: Self = Vector {
                    main,
                    reject: lines.next().unwrap(),
                    pk: lines
                        .next()
                        .unwrap()
                        .split(": ")
                        .nth(1)
                        .unwrap()
                        .to_string(),
                    sk: lines
                        .next()
                        .unwrap()
                        .split(": ")
                        .nth(1)
                        .unwrap()
                        .to_string(),
                    e_seed: lines.next().unwrap(),
                    ct: lines
                        .next()
                        .unwrap()
                        .split(": ")
                        .nth(1)
                        .unwrap()
                        .to_string(),
                    ss: lines
                        .next()
                        .unwrap()
                        .split(": ")
                        .nth(1)
                        .unwrap()
                        .to_string(),
                };
                let _ = lines.next().unwrap();
                vec.check(dbg!(i));
                i += 1;
            } else {
                break;
            }
        }
    }

    fn check(&self, i: usize) {
        struct UpdateVec(Vec<u8>);

        impl Update for UpdateVec {
            fn update(&mut self, data: &[u8]) {
                self.0.extend_from_slice(data);
            }
        }

        let main = hex::decode(&self.main).unwrap().try_into().unwrap();
        let reject = hex::decode(&self.reject).unwrap().try_into().unwrap();
        let (sk, pk) = key_pair::<DIM>(KeySeed { main, reject });
        let mut v = UpdateVec(vec![]);
        pk.to_bytes(&mut v);
        assert_eq!(self.pk, hex::encode(v.0), "{i}");

        let seed = hex::decode(&self.e_seed).unwrap().try_into().unwrap();
        let (ct, ss) = encapsulate(seed, &pk);
        let mut v = UpdateVec(vec![]);
        ct.to_bytes(&mut v);
        assert_eq!(self.ct, hex::encode(v.0), "{i}");

        assert_eq!(self.ss, hex::encode(&ss), "{i}");

        let ss = decapsulate(&sk, &pk, &ct);
        assert_eq!(self.ss, hex::encode(&ss), "{i}");
    }
}
