use num_bigint::{BigUint, RandBigInt};
use rand::distributions::Alphanumeric;
use rand::Rng;

pub struct ZKP {
    pub q: BigUint,
    pub p: BigUint,
    pub alpha: BigUint,
    pub beta: BigUint,
}

impl ZKP {
    // alpha ^ x mod p
    // output = n ^ exp mod p
    pub fn exponentiate(n: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
        n.modpow(exponent, modulus)
    }


    // output  = s = k - c * x mod q
    pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        if *k >= c * x {
            (k - c * x).modpow(&BigUint::from(1u32), &self.q)
        } else {
            (&self.q - (c * x - k)).modpow(&BigUint::from(1u32), &self.q)
        }
    }

    // cond1: r1 = alpha ^ s * y1^c
    // cond2: r2 = beta ^ s * y2^c
    pub fn verify(&self, r1: &BigUint, r2: &BigUint,y1: &BigUint, y2: &BigUint, c: &BigUint, s: &BigUint) -> bool {
        let cond1 = *r1 == (&self.alpha.modpow(s, &self.p) * y1.modpow(c, &self.p)).modpow(&BigUint::from(1u32), &self.p);
        let cond2 = *r2 == (&self.beta.modpow(s, &self.p) * y2.modpow(c, &self.p)).modpow(&BigUint::from(1u32), &self.p);
        cond1 && cond2
    }

    pub fn generate_random_below(limit: &BigUint) -> BigUint {
        let mut rng = rand::thread_rng();
        let random = rng.gen_biguint_below(limit);
        random
    }

    pub fn get_constants() -> (BigUint, BigUint, BigUint, BigUint) {
        let p = BigUint::from_bytes_be(
            &hex::decode("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371").expect("Invalid hex string"),
        );
        let q = BigUint::from_bytes_be(
            &hex::decode("801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB").expect("Invalid hex string"),
        );

        let alpha = BigUint::from_bytes_be(
            &hex::decode("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA").expect("Invalid hex string"),
        );
        let exp =  BigUint::from_bytes_be(&hex::decode("266FEA1E5C41564B777E69").unwrap());

        // beta = alpha^i is also a generator
        let beta = alpha.modpow(&exp, &p);

        (alpha, beta, p, q)
    }

    pub fn generate_random_string(size: usize) -> String {
        let mut rng = rand::thread_rng();
        rng.sample_iter(&Alphanumeric).take(size).map(char::from).collect()
    }
}

// // alpha ^ x mod p
// // output = n ^ exp mod p
// pub fn exponentiate(n: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
//     n.modpow(exponent, modulus)
// }

// // output  = s = k - c * x mod q
// pub fn solve(k: &BigUint, c: &BigUint, x: &BigUint,  q: &BigUint) -> BigUint {
//     if *k >= c * x {
//         (k - c * x).modpow(&BigUint::from(1u32), q)
//     } else {
//         (q - (c * x - k)).modpow(&BigUint::from(1u32), q)
//     }
// }

// // cond1: r1 = alpha ^ s * y1^c
// // cond2: r2 = beta ^ s * y2^c
// pub fn verify(r1: &BigUint, r2: &BigUint,y1: &BigUint, y2: &BigUint, alpha: &BigUint,  beta: &BigUint, c: &BigUint, s: &BigUint, p: &BigUint) -> bool {
//     let cond1 = *r1 == (alpha.modpow(s, p) * y1.modpow(c, p)).modpow(&BigUint::from(1u32), &p);
//     let cond2 = *r2 == (beta.modpow(s, p) * y2.modpow(c, p)).modpow(&BigUint::from(1u32), &p);
//     cond1 && cond2
// }



mod test {
    use super::*;

    #[test]
    fn test_toy_example() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let zkp = ZKP {
            q: q.clone(),
            p: p.clone(),
            alpha: alpha.clone(),
            beta: beta.clone(),
        };

        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);

        let c = BigUint::from(4u32);

        let y1 = ZKP::exponentiate(&alpha, &x, &p);
        let y2 = ZKP::exponentiate(&beta, &x, &p);

        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let r1 = ZKP::exponentiate(&alpha, &k, &p);
        let r2 = ZKP::exponentiate(&beta, &k, &p);
        assert_eq!(r1, BigUint::from(8u32));
        assert_eq!(r2, BigUint::from(4u32));

        let s = zkp.solve(&k, &c, &x);
        assert_eq!(s, BigUint::from(5u32));

        let x_fake = BigUint::from(7u32);
        let s_fake = zkp.solve(&k, &c, &x_fake);

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s_fake);
        assert_eq!(!result, false);
    }

    #[test]
    fn test_toy_example_with_random() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let zkp = ZKP {
            q: q.clone(),
            p: p.clone(),
            alpha: alpha.clone(),
            beta: beta.clone(),
        };

        let x = BigUint::from(6u32);
        let k = ZKP::generate_random_below(&q);

        let c = ZKP::generate_random_below( &q);

        let y1 = ZKP::exponentiate(&alpha, &x, &p);
        let y2 = ZKP::exponentiate(&beta, &x, &p);

        let r1 = ZKP::exponentiate(&alpha, &k, &p);
        let r2 = ZKP::exponentiate(&beta, &k, &p);
        let s = zkp.solve(&k, &c, &x);

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert_eq!(result, true);
    }


    #[test]
    fn test_1024_bits_constants() {
        //
        //    Reference: https://www.rfc-editor.org/rfc/rfc5114#page-15
        //
        //    The hexadecimal value of the prime is:
        //
        //    p = B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
        //        9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
        //        13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
        //        98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
        //        A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
        //        DF1FB2BC 2E4A4371
        //
        //    The hexadecimal value of the generator is:
        //
        //    g = A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
        //        D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
        //        160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
        //        909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
        //        D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
        //        855E6EEB 22B3B2E5
        //
        //    The generator generates a prime-order subgroup of size:
        //    q = F518AA87 81A8DF27 8ABA4E7D 64B7CB9D 49462353
        //
        let p = BigUint::from_bytes_be(
            &hex::decode("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371").expect("Invalid hex string"),
        );
        let q = BigUint::from_bytes_be(
            &hex::decode("801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB").expect("Invalid hex string"),
        );

        let alpha = BigUint::from_bytes_be(
            &hex::decode("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA").expect("Invalid hex string"),
        );

        // beta = alpha^i is also a generator
        let beta = alpha.modpow(&ZKP::generate_random_below(&q), &p);

        let zkp = ZKP {
            q: q.clone(),
            p: p.clone(),
            alpha: alpha.clone(),
            beta: beta.clone(),
        };

        let x = ZKP::generate_random_below(&q);
        let k = ZKP::generate_random_below(&q);

        let c = ZKP::generate_random_below(&q);



    }
}