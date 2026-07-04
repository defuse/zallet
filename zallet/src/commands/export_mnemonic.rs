use abscissa_core::Runnable;
use tokio::io::{self, AsyncWriteExt};
use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_client_sqlite::AccountUuid;

use crate::{
    cli::ExportMnemonicCmd,
    commands::AsyncRunnable,
    components::{database::Database, keystore::KeyStore},
    error::{Error, ErrorKind},
    fl,
    prelude::*,
};

impl AsyncRunnable for ExportMnemonicCmd {
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();
        let _lock = config.lock_datadir()?;

        let db = Database::open(&config).await?;
        let wallet = db.handle().await?;
        let keystore = KeyStore::new(&config, db)?;

        let account = wallet
            .get_account(AccountUuid::from_uuid(self.account_uuid))
            .map_err(|e| ErrorKind::Generic.context(e))?
            .ok_or_else(|| ErrorKind::Generic.context(fl!("err-account-not-found")))?;

        let derivation = account
            .source()
            .key_derivation()
            .ok_or_else(|| ErrorKind::Generic.context(fl!("err-account-no-payment-source")))?;

        let encrypted_mnemonic = keystore
            .export_mnemonic(derivation.seed_fingerprint(), self.armor)
            .await?;

        let mut stdout = io::stdout();
        stdout
            .write_all(&encrypted_mnemonic)
            .await
            .map_err(|e| ErrorKind::Generic.context(e))?;
        stdout
            .flush()
            .await
            .map_err(|e| ErrorKind::Generic.context(e))?;

        // The exported mnemonic only backs up funds derived from this seed. If the
        // wallet also holds spend authority that no mnemonic can regenerate
        // (imported Sapling keys, migrated transparent keys, or legacy seeds),
        // warn that this is not a complete backup. The warning goes to stderr so
        // it does not corrupt the mnemonic written to stdout (which is typically
        // redirected to a file).
        let has_legacy_seeds = !keystore.list_legacy_seed_fingerprints().await?.is_empty();
        let has_standalone_keys = keystore.has_standalone_keys().await?;
        if has_legacy_seeds || has_standalone_keys {
            eprintln!();
            eprintln!("WARNING: this mnemonic is NOT a complete backup of your wallet.");
            eprintln!("This wallet also holds spending keys that CANNOT be recovered from any");
            eprintln!("mnemonic (imported Sapling keys, migrated transparent keys, and/or legacy");
            eprintln!("seeds). To back those up you must ALSO keep a secure copy of BOTH:");
            eprintln!("  - your Zallet wallet database (wallet.db in your datadir), and");
            eprintln!("  - the age encryption identity file (the file named by the");
            eprintln!("    keystore.encryption_identity config option); wallet.db is encrypted");
            eprintln!("    to it and cannot be decrypted without it.");
            eprintln!("There is currently no backup RPC or command for this key material.");
        }

        Ok(())
    }
}

impl Runnable for ExportMnemonicCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}
