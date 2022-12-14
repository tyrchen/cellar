use base64::engine::fast_portable::{self, FastPortable};
use cellar_core::{generate_app_key, init, KeyType};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::RngCore;

const URL_SAFE_ENGINE: FastPortable =
    FastPortable::from(&base64::alphabet::URL_SAFE, fast_portable::NO_PAD);

criterion_group!(benches, gen_app_key);
criterion_main!(benches);

fn gen_app_key(c: &mut Criterion) {
    c.bench_function("app key", |b| {
        b.iter(|| {
            let mut rng = rand::thread_rng();
            let mut buf: [u8; 16] = Default::default();
            let mut info: [u8; 32] = Default::default();
            rng.fill_bytes(&mut buf);
            rng.fill_bytes(&mut info);
            let passphrase = base64::encode_engine(buf, &URL_SAFE_ENGINE);
            let aux = init(&passphrase).unwrap();
            generate_app_key(&passphrase, &aux, &info, KeyType::Password).unwrap();
        })
    });
}
