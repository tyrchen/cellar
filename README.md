# Cellar

Cellar is a simple password generation / retrival tool inspired by [Technology Preview for secure value recovery](https://signal.org/blog/secure-value-recovery/). The main algorithm is (a little bit tweak against original one):

```bash
salt            = Secure-Random(output_length=32)
stretched_key   = Argon2(passphrase=user_passphrase, salt=salt)

auth_key        = HMAC-BLAKE2s(key=stretched_key, "Auth Key")
c1              = HMAC-BLAKE2s(key=stretched_key, "Master Key")
c2              = Secure-Random(output_length=32)
encrypted_c2    = ChaCha20(c2, key=auth_key, nonce=salt[0..CHACHA20_NONCE_LENGTH])

master_key      = HMAC-BLAKE2s(key=c1, c2)
application_key = HMAC-BLAKE2s(key=master_key, "app info, e.g. yourname@gmail.com")
```

The main purpose of cellar is to allow people to just remember a single password, and by using the above algorithm, one can create as many application passwords which is cryptographically strong. A user just need to store the randomly gnerated salt and encrypted_c2 in local disk and the cloud so when she wants to generate or retrieve an application password, she could use her passphrase, plus the salt and encrypted_c2 to recover the master key, and then derive the application password. As long as user kept the passphrase secret in her mind, all the application passwords are secure. Even if the salt and encrypted_c2 are leaked, a hacker still need to brute force the master key.

By using Cellar, you don't need to trust the cloud provider to store your passwords, and you don't need to bother to remember a large number of passwords for different sites / applications.

Cellar is a MVP at the moment. Some future items:

* [x] support hierarchical keys
* [x] zeroize keys for security purpose
* [ ] generate password by a set of rules (min / max / character set)
* [ ] record the app_info and the rule it uses in an encrypted file
* [ ] provide a WebUI to make it easy to use

## Usage

### cellar init

Initialize a cellar (default: `$HOME/.cellar/default.toml`)

```bash
$ cellar init
Creating cellar "$HOME/.cellar/default.toml"
Password: [hidden]
Your cellar "$HOME/.cellar/default.toml" is created! Feel free to use `cellar generate` to create or display your application password.
```

after initialization, a `~/.cellar/default.toml` is generated. This files stores the random salt and the encrypted random seed like this:

```bash
$ cat ~/.cellar/default.toml
salt = "C6TQW8joYp2XoIkvaCNfo0ihJ3OacxlTbx68_oW8pF4"
encrypted_seed = "bHn5Lu3yX0g68rRJ4lTOwAvx_uMDFaBnZ_WMkJSU8TM"
```

Note that even if you regenerate the cellar with the same password you will get very different master key and derived application keys. So make sure you backup this file into your private cloud.

### cellar generate

Generate an application password:

```bash
$ cellar generate --app-info "user@gmail.com"
Password: [hidden]
Password for user@gmail.com: FLugCDPDQ5NP_Nb0whUMwY2YD3wMWqoGcoywqqZ_JSU
```

Generate hierarchical keys:

```bash
# generate parent key
$ cellar generate -i "apps"
Password: [hidden]
Key for apps: 6CAakhEv_L2purgTfUasrvA9qgRZrQGdETDohSbBvNI

# generate app key by using parent key
$ cellar generate -i "my/awesome/app" --use-parent-key
Parent Key: [hidden]
Key for my/awesome/app: ZFqgQZK4Sx4GgwLn9D-qmhYE5gw0QbUSl4I8HaTseZs

# it would be the same as generate the whole hierarchical key with master password
$ cellar generate -i "apps/my/awesome/app"
Password: [hidden]
Key for apps/my/awesome/app: ZFqgQZK4Sx4GgwLn9D-qmhYE5gw0QbUSl4I8HaTseZs
```

## Benchmark

If you'd run benchmark for cellar, use `make bench_cellar`. Argon2 will make the generation of the stretched key slow on purpose, the the default sample size would make the benchmark unbearly slow. An application password generation would spend around 18ms in my 2017 mbp.

```bash
$ make bench_cellar
cargo bench --bench bench_cellar --  --sample-size 10
   Compiling cellar-core v0.1.0 (/Users/tchen/projects/mycode/cellar/cellar-core)
    Finished bench [optimized] target(s) in 3.92s
     Running /Users/tchen/.target/release/deps/bench_cellar-f87c142f98bb458c
app key                 time:   [17.812 ms 17.970 ms 18.161 ms]
                        change: [-1.8875% -0.3966% +1.2260%] (p = 0.65 > 0.05)
                        No change in performance detected.
```
