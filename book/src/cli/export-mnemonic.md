# The `export-mnemonic` command

`zallet export-mnemonic` enables a BIP 39 mnemonic to be exported from a Zallet wallet.

The command takes the UUID of the account for which the mnemonic should be exported. You
can obtain this from a running Zallet wallet with `zallet rpc z_listaccounts`.

The mnemonic is encrypted to the same `age` identity that the wallet uses to internally
encrypt key material. You can then use a tool like [`rage`] to decrypt the resulting
file.

> ## ⚠️ The mnemonic is not always a complete backup
>
> `export-mnemonic` backs up **only** funds derived from this seed. A wallet can also hold
> spend authority that **cannot** be recovered from any mnemonic: Sapling keys imported
> with `z_importkey`, transparent keys and legacy seeds brought in by
> [`zallet migrate-zcashd-wallet`], and any other standalone key material. That material
> lives only in the Zallet wallet database.
>
> To back it up, you must **also** keep a secure copy of **both** the `wallet.db` file
> *and* the age encryption identity file (the file named by the `keystore.encryption_identity`
> config option). `wallet.db` is encrypted to that identity and cannot be decrypted without
> it. There is currently no backup RPC or command for this key material. When the wallet
> contains such keys, `export-mnemonic` prints this warning to `stderr`.

```
$ zallet export-mnemonic --armor 514ab5f4-62bd-4d8c-94b5-23fa8d8d38c2 >mnemonic.age
$ echo mnemonic.age
-----BEGIN AGE ENCRYPTED FILE-----
...
-----END AGE ENCRYPTED FILE-----
$ rage -d -i path/to/encrypted-identity.txt mnemonic.age
some seed phrase ...
```

[`rage`](https://github.com/str4d/rage)

[`zallet migrate-zcashd-wallet`]: migrate-zcashd-wallet.md
