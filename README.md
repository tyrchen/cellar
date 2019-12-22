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

* [ ] generate password by a set of rules (min / max / character set)
* [ ] record the app_info and the rule it uses in an encrypted file
* [ ] provide a WebUI to make it easy to use

## Usage

## cellar init

Initialize a cellar (default: `$HOME/.cellar/default.toml`)

```bash
$ cellar init
Creating cellar "$HOME/.cellar/default.toml"
Password: [hidden]
Your cellar "$HOME/.cellar/default.toml" is created! Feel free to use `cellar generate` to create or display your application password.
```

## cellar generate

Generate an application password.

```bash
$ cellar generate --app-info "user@gmail.com"
Password: [hidden]
Password for user@gmail.com: FLugCDPDQ5NP_Nb0whUMwY2YD3wMWqoGcoywqqZ_JSU
```
