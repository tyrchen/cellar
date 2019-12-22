use base64::URL_SAFE_NO_PAD;
use cellar_core::{generate_app_key, init};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::RngCore;

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
            let passphrase = base64::encode_config(&buf, URL_SAFE_NO_PAD);
            let aux = init(&passphrase).unwrap();
            generate_app_key(&passphrase, &aux, &info).unwrap();
        })
    });
}
