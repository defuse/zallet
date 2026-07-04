use std::{
    collections::{BTreeMap, HashMap, HashSet, hash_map::Entry},
    path::PathBuf,
};

use abscissa_core::Runnable;

use bip0039::{English, Mnemonic};
use secp256k1::PublicKey;
use secrecy::{ExposeSecret, SecretVec};
use shardtree::error::ShardTreeError;
use transparent::address::TransparentAddress;
use zcash_client_backend::{
    data_api::{
        Account as _, AccountBirthday, AccountPurpose, AccountSource, WalletRead, WalletWrite as _,
        Zip32Derivation, chain::ChainState,
    },
    decrypt_transaction,
};
use zcash_client_sqlite::error::SqliteClientError;
use zcash_keys::keys::{
    DerivationError, UnifiedFullViewingKey,
    zcashd::{PathParseError, ZcashdHdDerivation},
};
use zcash_primitives::{block::BlockHash, transaction::Transaction};
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters};
use zcash_script::script::{Code, Redeem};
use zewif_zcashd::{
    BDBDump, DBKey, ZcashdDump, ZcashdParser, ZcashdWallet,
    zcashd_wallet::transparent::WatchScriptKind,
};
use zip32::{AccountId, fingerprint::SeedFingerprint};

use crate::{
    cli::MigrateZcashdWalletCmd,
    components::{
        chain::{Chain, ChainBackend, ChainError, ChainView},
        database::Database,
        keystore::KeyStore,
    },
    error::{Error, ErrorKind},
    fl,
    prelude::*,
};

use super::{AsyncRunnable, migrate_zcash_conf};

/// The ZIP 32 account identifier of the zcashd account used for maintaining legacy `getnewaddress`
/// and `z_getnewaddress` semantics after the zcashd v4.7.0 upgrade to support using
/// mnemonic-sourced HD derivation for all addresses in the wallet.
pub const ZCASHD_LEGACY_ACCOUNT: AccountId = AccountId::const_from_u32(0x7FFFFFFF);
/// A source string to identify an account as being derived from the randomly generated binary HD
/// seed used for Sapling key generation prior to the zcashd v4.7.0 upgrade.
pub const ZCASHD_LEGACY_SOURCE: &str = "zcashd_legacy";
/// A source string to identify an account as being derived from the mnemonic HD seed used for
/// key derivation after the zcashd v4.7.0 upgrade.
pub const ZCASHD_MNEMONIC_SOURCE: &str = "zcashd_mnemonic";

impl AsyncRunnable for MigrateZcashdWalletCmd {
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();

        if !self.this_is_alpha_code_and_you_will_need_to_redo_the_migration_later {
            return Err(ErrorKind::Generic.context(fl!("migrate-alpha-code")).into());
        }

        // Start monitoring the chain (skip if --no-scan).
        let (chain, _chain_indexer_task_handle) = if self.no_scan {
            (None, None)
        } else {
            let (c, h) = ChainBackend::new(&config).await?;
            (Some(c), Some(h))
        };
        let db = Database::open(&config).await?;
        let keystore = KeyStore::new(&config, db.clone())?;

        info!("Dumping zcashd wallet");
        let (wallet, unparsed_keys) = self.dump_wallet()?;
        info!("Wallet dumped");

        Self::migrate_zcashd_wallet(
            db,
            keystore,
            chain,
            wallet,
            unparsed_keys,
            self.buffer_wallet_transactions,
            self.allow_multiple_wallet_imports,
            self.no_scan,
        )
        .await?;

        Ok(())
    }
}

impl MigrateZcashdWalletCmd {
    fn dump_wallet(&self) -> Result<(ZcashdWallet, HashSet<DBKey>), MigrateError> {
        let wallet_path = if self.path.is_relative() {
            if let Some(datadir) = self.zcashd_datadir.as_ref() {
                datadir.join(&self.path)
            } else {
                migrate_zcash_conf::zcashd_default_data_dir()
                    .ok_or(MigrateError::Wrapped(ErrorKind::Generic.into()))?
                    .join(&self.path)
            }
        } else {
            self.path.to_path_buf()
        };

        // Resolve the `db_dump` utility. An explicit `--zcashd-install-dir` uses that
        // installation's binary; otherwise prefer the BDB 6.2 `db_dump` vendored by
        // `zewif-zcashd` (via `BDBDump::from_file`), which falls back to one on the `PATH`.
        let db_dump_unavailable = || {
            MigrateError::Wrapped(
                ErrorKind::Generic
                    .context(fl!("err-migrate-wallet-db-dump-not-found"))
                    .into(),
            )
        };
        let db_dump = match &self.zcashd_install_dir {
            Some(path) => {
                let db_dump_path = path.join("zcutil").join("bin").join("db_dump");
                if !db_dump_path.is_file() {
                    return Err(db_dump_unavailable());
                }
                BDBDump::from_file_with_path(db_dump_path.as_path(), wallet_path.as_path())
            }
            None => {
                // `from_file` tries the vendored `db_dump` and then one on the `PATH`. If
                // it fails and there is no `db_dump` on the `PATH` either, report it as
                // unavailable rather than surfacing a raw execution error.
                let dumped = BDBDump::from_file(wallet_path.as_path());
                if dumped.is_err() && which::which("db_dump").is_err() {
                    return Err(db_dump_unavailable());
                }
                dumped
            }
        }
        .map_err(|e| MigrateError::Zewif {
            error_type: ZewifError::BdbDump,
            wallet_path: wallet_path.to_path_buf(),
            error: e,
        })?;

        let zcashd_dump =
            ZcashdDump::from_bdb_dump(&db_dump, self.allow_warnings).map_err(|e| {
                MigrateError::Zewif {
                    error_type: ZewifError::ZcashdDump,
                    wallet_path: wallet_path.clone(),
                    error: e,
                }
            })?;

        let (zcashd_wallet, unparsed_keys) =
            ZcashdParser::parse_dump(&zcashd_dump, !self.allow_warnings).map_err(|e| {
                MigrateError::Zewif {
                    error_type: ZewifError::ZcashdDump,
                    wallet_path,
                    error: e,
                }
            })?;

        Ok((zcashd_wallet, unparsed_keys))
    }

    fn check_network(
        zewif_network: zewif::Network,
        network_type: NetworkType,
    ) -> Result<NetworkType, MigrateError> {
        match (zewif_network, network_type) {
            (zewif::Network::Main, NetworkType::Main) => Ok(()),
            (zewif::Network::Test, NetworkType::Test) => Ok(()),
            (zewif::Network::Regtest, NetworkType::Regtest) => Ok(()),
            (wallet_network, db_network) => Err(MigrateError::NetworkMismatch {
                wallet_network,
                db_network,
            }),
        }?;

        Ok(network_type)
    }

    fn parse_mnemonic(mnemonic: &str) -> Result<Option<Mnemonic>, bip0039::Error> {
        (!mnemonic.is_empty())
            .then(|| Mnemonic::<English>::from_phrase(mnemonic))
            .transpose()
    }

    #[allow(clippy::too_many_arguments)]
    async fn migrate_zcashd_wallet<C: Chain>(
        db: Database,
        keystore: KeyStore,
        chain: Option<C>,
        wallet: ZcashdWallet,
        unparsed_keys: HashSet<DBKey>,
        buffer_wallet_transactions: bool,
        allow_multiple_wallet_imports: bool,
        no_scan: bool,
    ) -> Result<(), MigrateError> {
        let mut db_data = db.handle().await?;
        let network_params = *db_data.params();
        Self::check_network(wallet.network(), network_params.network_type())?;

        // Counters feeding the end-of-migration summary (see the `MigrationSummary`
        // block at the end of this function). The `skipped_*` counters declared
        // further below feed into the same summary.
        let mut imported_sapling_standalone = 0usize;
        let mut imported_watchonly_pubkeys = 0usize;
        let mut imported_watchonly_scripts = 0usize;
        let mut skipped_unsupported_scripts = 0usize;

        // Collect transparent material imported via `zcashd`'s `importpubkey` (P2PK
        // entries in `watch_scripts()`) and `importaddress <redeemScript> "" true`
        // (entries in `cscripts()`). Address-only entries (raw P2PKH / P2SH hashes with
        // no associated pubkey or redeem script) cannot be represented in the Zallet
        // wallet schema; count and warn-log them so users see what was dropped. P2SH
        // entries with a matching `cscripts()` record are imported via that path below.
        let mut skipped_p2pkh_address_only = 0usize;
        let mut skipped_p2sh_address_only = 0usize;
        let mut skipped_nonstandard = 0usize;
        let mut skipped_malformed_pubkeys = 0usize;
        let mut skipped_uncompressed_pubkeys = 0usize;
        let watchonly_pubkeys = wallet
            .watch_scripts()
            .iter()
            .filter_map(|w| match w.kind() {
                // `import_standalone_transparent_pubkey` always derives the stored
                // P2PKH from `PublicKey::serialize()` (the 33-byte compressed form),
                // so an uncompressed (65-byte) pubkey would be tracked under a
                // different address than `zcashd` had on-chain. Skip with a warn
                // rather than silently migrating to the wrong address.
                WatchScriptKind::P2PK(pubkey) if !pubkey.is_compressed() => {
                    skipped_uncompressed_pubkeys += 1;
                    None
                }
                WatchScriptKind::P2PK(pubkey) => match PublicKey::from_slice(pubkey.as_slice()) {
                    Ok(pk) => Some(pk),
                    Err(_) => {
                        skipped_malformed_pubkeys += 1;
                        None
                    }
                },
                WatchScriptKind::P2PKH(_) => {
                    skipped_p2pkh_address_only += 1;
                    None
                }
                WatchScriptKind::P2SH(_) => {
                    skipped_p2sh_address_only += 1;
                    None
                }
                WatchScriptKind::Other(_) => {
                    skipped_nonstandard += 1;
                    None
                }
            })
            .collect::<Vec<_>>();
        if skipped_uncompressed_pubkeys > 0 {
            warn!(
                "Skipped {} watch-only P2PK entries with uncompressed public keys; \
                 the Zallet wallet schema only supports compressed-form pubkey \
                 imports, so these would be tracked under a different address than \
                 `zcashd` had on-chain.",
                skipped_uncompressed_pubkeys,
            );
        }
        if skipped_malformed_pubkeys > 0 {
            warn!(
                "Skipped {} watch-only P2PK entries with malformed public keys.",
                skipped_malformed_pubkeys,
            );
        }
        if skipped_p2pkh_address_only > 0 {
            warn!(
                "Skipped {} watch-only P2PKH address-only entries (from `zcashd`'s \
                 `importaddress <p2pkhaddress>`); these cannot be migrated without the \
                 corresponding pubkey.",
                skipped_p2pkh_address_only,
            );
        }
        if skipped_p2sh_address_only > 0 {
            warn!(
                "Skipped {} watch-only P2SH address-only entries (`watchs` records with \
                 no matching `cscript`). P2SH entries with a matching redeem script are \
                 imported via the `cscript` path.",
                skipped_p2sh_address_only,
            );
        }
        if skipped_nonstandard > 0 {
            warn!(
                "Skipped {} watch-only entries with non-standard script kinds.",
                skipped_nonstandard,
            );
        }
        let mut skipped_unparseable_scripts = 0usize;
        let watchonly_scripts = wallet
            .cscripts()
            .values()
            .filter_map(|s| match Redeem::parse(&Code(s.as_ref().to_vec())) {
                Ok(redeem) => Some(redeem),
                Err(e) => {
                    skipped_unparseable_scripts += 1;
                    warn!(
                        "Failed to parse watch-only redeem script (hex: {}): {}",
                        hex::encode(s.as_ref()),
                        e,
                    );
                    None
                }
            })
            .collect::<Vec<_>>();
        if skipped_unparseable_scripts > 0 {
            warn!(
                "Skipped {} watch-only redeem scripts that failed to parse in total.",
                skipped_unparseable_scripts,
            );
        }

        let existing_zcash_sourced_accounts = db_data.get_account_ids()?.into_iter().try_fold(
            HashSet::new(),
            |mut found, account_id| {
                let account = db_data
                    .get_account(account_id)?
                    .expect("account exists for just-retrieved id");

                match account.source() {
                    AccountSource::Derived {
                        derivation,
                        key_source,
                    } if key_source.as_ref() == Some(&ZCASHD_MNEMONIC_SOURCE.to_string()) => {
                        found.insert(*derivation.seed_fingerprint());
                    }
                    _ => {}
                }

                Ok::<_, SqliteClientError>(found)
            },
        )?;

        let mnemonic_seed_data = match Self::parse_mnemonic(wallet.bip39_mnemonic().mnemonic())? {
            Some(m) => Some((
                SecretVec::new(m.to_seed("").to_vec()),
                keystore.encrypt_and_store_mnemonic(m).await?,
            )),
            None => None,
        };

        if !existing_zcash_sourced_accounts.is_empty() {
            if allow_multiple_wallet_imports {
                if let Some((seed, _)) = mnemonic_seed_data.as_ref() {
                    let seed_fp =
                        SeedFingerprint::from_seed(seed.expose_secret()).expect("valid length");
                    if existing_zcash_sourced_accounts.contains(&seed_fp) {
                        return Err(MigrateError::DuplicateImport(seed_fp));
                    }
                }
            } else {
                return Err(MigrateError::MultiImportDisabled);
            }
        }

        // Obtain information about the current state of the chain, so that we can set the recovery
        // height properly.
        let (chain_view, chain_tip) = if let Some(chain) = &chain {
            let chain_view = chain.snapshot().await?;
            let tip = chain_view.tip().await?;
            // A chain tip at height zero means the chain consists of only the genesis
            // block, and contains no usable tree state.
            let tip_height = (tip.height > BlockHeight::from_u32(0)).then_some(tip.height);
            (Some(chain_view), tip_height)
        } else {
            info!("No-scan mode: skipping chain scanning");
            (None, None)
        };
        let sapling_activation = network_params
            .activation_height(NetworkUpgrade::Sapling)
            .expect("Sapling activation height is defined.");

        // Collect an index from block hash to block height for all transactions known to the
        // wallet that appear in the main chain. This only runs when we have a chain subscriber;
        // without one, all transactions are stored as unmined and a later scan will assign
        // accurate heights. Address exposure is handled separately via
        // `mark_transparent_addresses_exposed` below.
        info!(
            "Wallet contains {} transactions",
            wallet.transactions().len(),
        );
        let mut main_chain_block_heights = HashMap::new();
        if let Some(chain_view) = chain_view.as_ref() {
            for wallet_tx in wallet.transactions().values() {
                let block_hash = BlockHash(*wallet_tx.hash_block().as_ref());
                // Skip transactions that were unmined when the zcashd wallet was last written.
                if block_hash.0 != [0; 32]
                    && let Entry::Vacant(entry) = main_chain_block_heights.entry(block_hash)
                {
                    // Ignore any blocks that are not in the main chain.
                    if let Some(height) = chain_view.block_height(&block_hash).await? {
                        entry.insert(height);
                    }
                }
            }
        }
        let mut tx_heights = HashMap::new();
        for (txid, wallet_tx) in wallet.transactions().iter() {
            let block_hash = BlockHash(*wallet_tx.hash_block().as_ref());
            tx_heights.insert(
                txid,
                (
                    main_chain_block_heights.get(&block_hash).cloned(),
                    buffer_wallet_transactions.then_some(wallet_tx),
                ),
            );
        }
        info!(
            "Wallet contains {} mined transactions",
            tx_heights.values().filter(|(h, _)| h.is_some()).count(),
        );

        // Since zcashd scans in linear order, we can reliably choose the earliest wallet
        // transaction's mined height as the birthday height, so long as it is in the "stable"
        // range. We don't have a good source of individual per-account birthday information at
        // this point; once we've imported all of the transaction data into the wallet then we'll
        // be able to choose per-account birthdays without difficulty.
        let wallet_birthday = if let Some(chain_view) = chain_view.as_ref() {
            // Fall back to the chain tip height, and then Sapling activation as a last resort.
            // If we have a birthday height, max() that with sapling activation; that will be
            // the minimum possible wallet birthday that is relevant to future recovery
            // scenarios.
            let birthday_height = tx_heights
                .values()
                .flat_map(|(h, _)| h)
                .min()
                .copied()
                .or(chain_tip)
                .map_or(sapling_activation, |h| std::cmp::max(h, sapling_activation));

            // Fetch the tree state corresponding to the last block prior to the wallet's
            // birthday height.
            let treestate_height = birthday_height.saturating_sub(1);
            let chain_state = chain_view.tree_state_as_of(treestate_height).await?.ok_or(
                ErrorKind::Generic.context(fl!(
                    "err-migrate-wallet-invalid-chain-data",
                    err = format!("missing tree state for height {treestate_height}")
                )),
            )?;

            AccountBirthday::from_parts(chain_state, chain_tip)
        } else {
            // In no-scan mode, no chain is available, and we cannot determine actual transaction
            // mined heights. Instead, we estimate the wallet's birthday, and then conservatively
            // mark each address with a mined transaction as exposed at that birthday height.
            //
            // We approximate the wallet birthday from transaction expiry heights. Expiry heights
            // are typically creation_height + 40 (the default TX_EXPIRY_DELTA in zcashd).
            // Subtracting 1000 gives a conservative lower bound on the earliest mined height.
            let birthday_height = wallet
                .transactions()
                .values()
                .map(|tx| u32::from(tx.transaction().expiry_height()))
                .filter(|&h| h > 0)
                .min()
                .map(|h| BlockHeight::from_u32(h.saturating_sub(1000)))
                .map(|h| std::cmp::max(h, sapling_activation))
                .unwrap_or(sapling_activation);

            AccountBirthday::from_parts(
                ChainState::empty(birthday_height, BlockHash([0; 32])),
                None,
            )
        };
        info!(
            "Setting the wallet birthday to height {}",
            wallet_birthday.height(),
        );

        let mnemonic_seed_fp = mnemonic_seed_data.as_ref().map(|(_, fp)| *fp);
        let legacy_transparent_account_uuid = if let Some((seed, _)) = mnemonic_seed_data.as_ref() {
            // Create the legacy account if there are any legacy transparent keys or any
            // imported watch-only transparent pubkeys / redeem scripts to store.
            if !wallet.keys().is_empty()
                || !watchonly_pubkeys.is_empty()
                || !watchonly_scripts.is_empty()
            {
                let (account, _) = db_data.import_account_hd(
                    &format!(
                        "zcashd post-v4.7.0 legacy transparent account {}",
                        u32::from(ZCASHD_LEGACY_ACCOUNT),
                    ),
                    seed,
                    ZCASHD_LEGACY_ACCOUNT,
                    &wallet_birthday,
                    Some(ZCASHD_MNEMONIC_SOURCE),
                )?;

                println!(
                    "{}",
                    fl!(
                        "migrate-wallet-legacy-seed-fp",
                        seed_fp = mnemonic_seed_fp
                            .expect("present for mnemonic seed")
                            .to_string()
                    )
                );

                Some(account.id())
            } else {
                None
            }
        } else {
            None
        };

        let legacy_seed_data = match wallet.legacy_hd_seed() {
            Some(d) => Some((
                SecretVec::new(d.seed_data().to_vec()),
                keystore
                    .encrypt_and_store_legacy_seed(&SecretVec::new(d.seed_data().to_vec()))
                    .await?,
            )),
            None => None,
        };
        let legacy_transparent_account_uuid =
            match (legacy_transparent_account_uuid, legacy_seed_data.as_ref()) {
                (Some(uuid), _) => {
                    // We already had a mnemonic seed and have created the mnemonic-based legacy
                    // account, so we don't need to do anything.
                    Some(uuid)
                }
                (None, Some((seed, _)))
                    if !wallet.keys().is_empty()
                        || !watchonly_pubkeys.is_empty()
                        || !watchonly_scripts.is_empty() =>
                {
                    // In this case, we have the legacy seed, but no mnemonic seed was ever derived
                    // from it, so this is a pre-v4.7.0 wallet. We construct the mnemonic in the same
                    // fashion as zcashd, by using the legacy seed as entropy in the generation of the
                    // mnemonic seed, and then import that seed and the associated legacy account so
                    // that we have an account to act as the "bucket of funds" for the transparent keys
                    // derived from system randomness.
                    let mnemonic = zcash_keys::keys::zcashd::derive_mnemonic(seed)
                        .ok_or(ErrorKind::Generic.context(fl!("err-failed-seed-fingerprinting")))?;

                    let seed = SecretVec::new(mnemonic.to_seed("").to_vec());
                    keystore.encrypt_and_store_mnemonic(mnemonic).await?;
                    let (account, _) = db_data.import_account_hd(
                        &format!(
                            "zcashd post-v4.7.0 legacy transparent account {}",
                            u32::from(ZCASHD_LEGACY_ACCOUNT),
                        ),
                        &seed,
                        ZCASHD_LEGACY_ACCOUNT,
                        &wallet_birthday,
                        Some(ZCASHD_MNEMONIC_SOURCE),
                    )?;

                    Some(account.id())
                }
                _ => None,
            };

        let legacy_seed_fp = legacy_seed_data.map(|(_, fp)| fp);

        // Add unified accounts. The only source of unified accounts in zcashd is derivation from
        // the mnemonic seed.
        if wallet.unified_accounts().account_metadata.is_empty() {
            info!("Wallet contains no unified accounts (z_getnewaccount was never used)");
        } else {
            info!(
                "Importing {} unified accounts (created with z_getnewaccount)",
                wallet.unified_accounts().account_metadata.len()
            );
        }
        for account in wallet.unified_accounts().account_metadata.values() {
            // The only way that a unified account could be created in zcashd was
            // to be derived from the mnemonic seed, so we can safely unwrap here.
            let (seed, seed_fp) = mnemonic_seed_data
                .as_ref()
                .expect("mnemonic seed should be present");

            assert_eq!(
                SeedFingerprint::from_bytes(*account.seed_fingerprint().as_bytes()),
                *seed_fp
            );

            let zip32_account_id = AccountId::try_from(account.zip32_account_id())
                .map_err(|_| MigrateError::AccountIdInvalid(account.zip32_account_id()))?;

            if db_data
                .get_derived_account(&Zip32Derivation::new(*seed_fp, zip32_account_id, None))?
                .is_none()
            {
                db_data.import_account_hd(
                    &format!(
                        "zcashd imported unified account {}",
                        account.zip32_account_id()
                    ),
                    seed,
                    zip32_account_id,
                    &wallet_birthday,
                    Some(ZCASHD_MNEMONIC_SOURCE),
                )?;
            }
        }

        // Sapling keys may originate from:
        // * The legacy HD seed, under a standard ZIP 32 key path
        // * The mnemonic HD seed, under a standard ZIP 32 key path
        // * The mnemonic HD seed, under the "legacy" account with an additional hardened path element
        // * Zcashd Sapling spending key import
        info!("Importing legacy Sapling keys"); // TODO: Expose how many there are in zewif-zcashd.
        for (idx, key) in wallet.sapling_keys().keypairs().enumerate() {
            if idx % 100 == 0 && idx > 0 {
                info!("Processed {} legacy Sapling keys", idx);
            }
            // `zewif_zcashd` parses to an earlier version of the `sapling` types, so we
            // must roundtrip through the byte representation into the version we need.
            let extsk = sapling::zip32::ExtendedSpendingKey::from_bytes(&key.extsk().to_bytes())
                .map_err(|_| ()) //work around missing Debug impl
                .expect("Sapling extsk encoding is stable across sapling-crypto versions");
            #[allow(deprecated)]
            let extfvk = extsk.to_extended_full_viewing_key();
            let ufvk =
                UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk.clone())?;

            let key_seed_fp = key
                .metadata()
                .seed_fp()
                .map(|seed_fp_bytes| SeedFingerprint::from_bytes(*seed_fp_bytes.as_bytes()));

            let derivation = key
                .metadata()
                .hd_keypath()
                .map(|keypath| ZcashdHdDerivation::parse_hd_path(&network_params, keypath))
                .transpose()?
                .zip(key_seed_fp)
                .map(|(derivation, key_seed_fp)| match derivation {
                    ZcashdHdDerivation::Zip32 { account_id } => {
                        Zip32Derivation::new(key_seed_fp, account_id, None)
                    }
                    ZcashdHdDerivation::Post470LegacySapling { address_index } => {
                        Zip32Derivation::new(
                            key_seed_fp,
                            ZCASHD_LEGACY_ACCOUNT,
                            Some(address_index),
                        )
                    }
                });

            // If the key is not associated with either of the seeds, treat it as a standalone
            // imported key
            if key_seed_fp != mnemonic_seed_fp && key_seed_fp != legacy_seed_fp {
                keystore
                    .encrypt_and_store_standalone_sapling_key(&extsk)
                    .await?;
                imported_sapling_standalone += 1;
            }

            let account_exists = match key_seed_fp.as_ref() {
                Some(fp) => db_data
                    .get_derived_account(&Zip32Derivation::new(
                        *fp,
                        ZCASHD_LEGACY_ACCOUNT,
                        derivation.as_ref().and_then(|d| d.legacy_address_index()),
                    ))?
                    .is_some(),
                None => db_data.get_account_for_ufvk(&ufvk)?.is_some(),
            };

            if !account_exists {
                db_data.import_account_ufvk(
                    &format!("zcashd legacy sapling {idx}"),
                    &ufvk,
                    &wallet_birthday,
                    AccountPurpose::Spending { derivation },
                    Some(ZCASHD_LEGACY_SOURCE),
                )?;
            }
        }

        // Import view-only Sapling keys added via `z_importviewingkey`. zcashd stores these as
        // `sapextfvk` BDB records; each extended FVK becomes its own view-only account, matching
        // how each spending-key entry becomes its own account above. If both `z_importkey` and
        // `z_importviewingkey` were called for the same key, the spending-key path already created
        // the account, so the `get_account_for_ufvk` check below skips the duplicate.
        let viewing_keys = wallet.sapling_extended_full_viewing_keys();
        info!("Importing {} view-only Sapling keys", viewing_keys.len());
        for (idx, zewif_extfvk) in viewing_keys.values().enumerate() {
            if idx % 100 == 0 && idx > 0 {
                info!("Processed {} view-only Sapling keys", idx);
            }
            // `zewif-zcashd` parses Sapling types against an older `sapling-crypto`. The ZIP 32
            // extended FVK encoding is 169 bytes and stable across versions, so round-trip through
            // bytes to get the version this crate uses.
            let mut bytes = [0u8; 169];
            zewif_extfvk
                .write(&mut bytes[..])
                .expect("Sapling extended FVK fits in 169 bytes");
            let extfvk = sapling::zip32::ExtendedFullViewingKey::read(&bytes[..])
                .expect("Sapling extended FVK encoding is stable across sapling-crypto versions");
            let ufvk = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk)?;

            if db_data.get_account_for_ufvk(&ufvk)?.is_none() {
                db_data.import_account_ufvk(
                    &format!("zcashd imported view-only sapling {idx}"),
                    &ufvk,
                    &wallet_birthday,
                    AccountPurpose::ViewOnly,
                    Some(ZCASHD_LEGACY_SOURCE),
                )?;
            }
        }

        // TODO: Move this into zewif-zcashd once we're out of dependency version hell.
        fn convert_key(
            key: &zewif_zcashd::zcashd_wallet::transparent::KeyPair,
        ) -> Result<zcash_keys::keys::transparent::Key, MigrateError> {
            // Check the encoding of the pubkey
            let _ = PublicKey::from_slice(key.pubkey().as_slice())?;
            let compressed = key.pubkey().is_compressed();

            let key = zcash_keys::keys::transparent::Key::der_decode(
                &SecretVec::new(key.privkey().data().to_vec()),
                compressed,
            )
            .map_err(|_| {
                ErrorKind::Generic.context(fl!(
                    "err-migrate-wallet-key-decoding",
                    err = "failed DER decoding"
                ))
            })?;

            Ok(key)
        }

        // Collect transparent addresses that need to be explicitly marked as exposed at the
        // wallet birthday; `mark_transparent_addresses_exposed` consumes this set below.
        // Otherwise `listaddresses` (which filters on `exposed_at_height IS NOT NULL`) would
        // never surface them. Two sources feed this set:
        //   * Every address imported standalone (privkey, pubkey, or P2SH redeem script) or
        //     watch-only (from `importaddress` / `importpubkey`), accumulated below as each
        //     import succeeds, since these have no on-chain derivation history that a chain
        //     scan would discover.
        //   * In no-scan mode, every address observed in the wallet's transaction set, since
        //     the chain will not be scanned to detect exposure heights.
        let mut to_expose: HashSet<TransparentAddress> = HashSet::new();

        let encryptor = keystore.encryptor().await?;
        let transparent_keypairs = wallet.keys().keypairs().collect::<Vec<_>>();
        let imported_transparent_keys = transparent_keypairs.len();
        info!(
            "Importing {} legacy standalone transparent keys",
            transparent_keypairs.len(),
        ); // TODO: Expose how many there are in zewif-zcashd.
        let encrypted_transparent_keys = transparent_keypairs
            .into_iter()
            .map(|key| {
                let key = convert_key(key)?;
                encryptor.encrypt_standalone_transparent_key(&key)
            })
            .collect::<Result<Vec<_>, _>>()?;
        keystore
            .store_encrypted_standalone_transparent_keys(&encrypted_transparent_keys)
            .await?;
        let standalone_pubkeys: Vec<PublicKey> = encrypted_transparent_keys
            .iter()
            .map(|key| *key.pubkey())
            .collect();
        to_expose.extend(
            standalone_pubkeys
                .iter()
                .map(TransparentAddress::from_pubkey),
        );
        db_data.import_standalone_transparent_pubkeys(
            legacy_transparent_account_uuid.ok_or(MigrateError::SeedNotAvailable)?,
            standalone_pubkeys.into_iter(),
        )?;

        // Import transparent addresses that were added to the `zcashd` wallet via
        // `importaddress` / `importpubkey` (i.e. watch-only imports). These are stored as
        // `watchs` and `cscript` records in `wallet.dat`, and `zewif-zcashd` does not
        // currently surface them through its parsed `ZcashdWallet` type.
        if !watchonly_pubkeys.is_empty() || !watchonly_scripts.is_empty() {
            let target_account =
                legacy_transparent_account_uuid.ok_or(MigrateError::SeedNotAvailable)?;

            imported_watchonly_pubkeys = watchonly_pubkeys.len();
            info!(
                "Importing {} watch-only transparent pubkeys",
                watchonly_pubkeys.len(),
            );
            to_expose.extend(
                watchonly_pubkeys
                    .iter()
                    .map(TransparentAddress::from_pubkey),
            );
            db_data.import_standalone_transparent_pubkeys(
                target_account,
                watchonly_pubkeys.into_iter(),
            )?;

            let watchonly_scripts_total = watchonly_scripts.len();
            info!(
                "Importing {} watch-only transparent redeem scripts",
                watchonly_scripts.len(),
            );
            for script in watchonly_scripts {
                let script_addr =
                    TransparentAddress::from_script_pubkey(&zcash_script::descriptor::sh(&script));
                // A P2SH descriptor should always produce a valid scriptPubKey from which
                // `TransparentAddress` can be parsed; if not, our exposure-marking step
                // below will silently miss this address, so log it.
                if script_addr.is_none() {
                    warn!(
                        "P2SH descriptor unexpectedly produced no `TransparentAddress`; \
                         the imported script will not be marked as exposed.",
                    );
                    debug_assert!(false, "sh() descriptor should always yield an address");
                }
                // `import_standalone_transparent_script` currently only accepts multisig
                // redeem scripts within the P2SH size limit; treat those rejections
                // (`SqliteClientError::BadAccountData`) as warn-and-skip so a single
                // unsupported script does not abort the migration. Any other error
                // (corrupted data, DB failure, conflict, ...) is propagated.
                match db_data.import_standalone_transparent_script(target_account, script) {
                    Ok(()) => {
                        if let Some(addr) = script_addr {
                            to_expose.insert(addr);
                        }
                    }
                    Err(SqliteClientError::BadAccountData(msg)) => {
                        skipped_unsupported_scripts += 1;
                        warn!("Skipping unsupported watch-only redeem script: {}", msg);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            if skipped_unsupported_scripts > 0 {
                warn!(
                    "Skipped {} unsupported watch-only redeem scripts in total.",
                    skipped_unsupported_scripts,
                );
            }
            imported_watchonly_scripts =
                watchonly_scripts_total.saturating_sub(skipped_unsupported_scripts);
        }

        // In no-scan mode, also mark every address observed in the wallet's transaction set,
        // since the chain will not be scanned to detect exposure heights.
        if no_scan {
            let mut buf = vec![];
            for wallet_tx in wallet.transactions().values() {
                buf.clear();
                wallet_tx.transaction().write(&mut buf)?;
                // We only read the transparent bundle here, so the branch id chosen here
                // is irrelevant: for v5+ txs the embedded branch id overrides this value,
                // and for earlier versions the branch id is only stored as metadata and
                // does not affect parsing of the transparent bundle. Any value works.
                //
                // The buffer-path below uses `BranchId::for_height` instead because it
                // re-parses the transaction for full decryption, where the branch id
                // does affect the result for earlier-version txs.
                let tx = Transaction::read(buf.as_slice(), BranchId::Sprout)?;
                if let Some(bundle) = tx.transparent_bundle() {
                    for vout in &bundle.vout {
                        if let Some(addr) = vout
                            .script_kind()
                            .as_ref()
                            .and_then(TransparentAddress::from_script_kind)
                        {
                            to_expose.insert(addr);
                        }
                    }
                }
            }
        }

        if !to_expose.is_empty() {
            // The upstream API rolls back the whole batch if any address is not tracked,
            // so filter to just the wallet's known receivers (external counterparties drop
            // out here).
            let mut known: HashSet<TransparentAddress> = HashSet::new();
            for account_id in db_data.get_account_ids()? {
                known.extend(
                    db_data
                        .get_transparent_receivers(
                            account_id, true, // include_change
                            true, // include_standalone
                        )?
                        .into_keys(),
                );
            }

            let birthday_height = wallet_birthday.height();
            let to_mark: Vec<(TransparentAddress, BlockHeight)> = to_expose
                .intersection(&known)
                .map(|addr| (*addr, birthday_height))
                .collect();
            // Surface any address we queued for exposure marking but that does not
            // appear in `known`. This should be empty in steady state; a non-zero
            // count signals that an import-path above produced a different address
            // than what was stored in the wallet (e.g. encoding mismatches), which
            // would otherwise be invisible.
            let dropped = to_expose.difference(&known).count();
            if dropped > 0 {
                warn!(
                    "{} transparent addresses queued for exposure marking were not \
                     tracked by any account and were skipped; an import path may \
                     have stored them under a different address.",
                    dropped,
                );
            }
            if !to_mark.is_empty() {
                db_data.mark_transparent_addresses_exposed(&to_mark)?;
                info!(
                    "Marked {} transparent addresses as exposed at birthday height {}",
                    to_mark.len(),
                    birthday_height,
                );
            }
        }

        // Since we've retrieved the raw transaction data anyway, preemptively store it for faster
        // access to balance & to set priorities in the scan queue.
        if buffer_wallet_transactions {
            info!("Importing transactions");

            // Fetch the UnifiedFullViewingKeys we are tracking
            let ufvks = db_data.get_unified_full_viewing_keys()?;

            let chain_tip_height = db_data.chain_height()?;

            // Assume that the zcashd wallet was shut down immediately after its last
            // transaction was mined. This will be accurate except in the following case:
            // - User mines a transaction in any older epoch.
            // - A network upgrade activates.
            // - User creates a transaction.
            // - User shuts down the wallet before the transaction is mined.
            let assumed_mempool_height = tx_heights
                .values()
                .flat_map(|(h, _)| h)
                .max()
                .map(|h| *h + 1);

            let mut buf = vec![];
            let decoded_txs = tx_heights
                .values()
                .flat_map(|(h, wallet_tx)| {
                    wallet_tx.map(|wallet_tx| {
                        let consensus_height = match h {
                            Some(h) => *h,
                            None => {
                                let expiry_height =
                                    u32::from(wallet_tx.transaction().expiry_height());
                                if expiry_height == 0 {
                                    // Transaction is unmined and unexpired, use fallback.
                                    assumed_mempool_height.ok_or_else(|| {
                                        ErrorKind::Generic
                                            .context(fl!("err-migrate-wallet-all-unmined"))
                                    })?
                                } else {
                                    // A transaction's expiry height is always in same epoch
                                    // as its eventual mined height.
                                    BlockHeight::from_u32(expiry_height)
                                }
                            }
                        };
                        let consensus_branch_id =
                            BranchId::for_height(&network_params, consensus_height);
                        // TODO: Use the same zcash_primitives version in zewif-zcashd
                        let tx = {
                            buf.clear();
                            wallet_tx.transaction().write(&mut buf)?;
                            Transaction::read(buf.as_slice(), consensus_branch_id)?
                        };
                        Ok((tx, *h))
                    })
                })
                .collect::<Result<Vec<_>, MigrateError>>()?;

            info!("Decrypting {} transactions", decoded_txs.len());
            let decrypted_txs = decoded_txs
                .iter()
                .enumerate()
                .map(|(i, (tx, mined_height))| {
                    if i % 1000 == 0 && i > 0 {
                        tracing::info!("Decrypted {i}/{} transactions", decoded_txs.len());
                    }
                    decrypt_transaction(
                        &network_params,
                        *mined_height,
                        chain_tip_height,
                        tx,
                        &ufvks,
                    )
                })
                .collect::<Vec<_>>();

            info!("Storing {} decrypted transactions", decrypted_txs.len());
            // TODO: Use chunking here if we add support for resuming migrations.
            db_data.store_decrypted_txs(decrypted_txs)?;
        } else {
            info!("Not importing transactions (--buffer-wallet-transactions not set)");
        }

        // Tally the wallet.dat records that the parser could not interpret (e.g.
        // the encrypted `c*` records written by an encrypted zcashd wallet). These
        // never reached any of the import paths above.
        let mut unparsed_records: BTreeMap<String, usize> = BTreeMap::new();
        for key in &unparsed_keys {
            *unparsed_records.entry(key.keyname.clone()).or_default() += 1;
        }

        let summary = MigrationSummary {
            mnemonic_seed: mnemonic_seed_fp.is_some(),
            legacy_hd_seed: legacy_seed_fp.is_some(),
            unified_accounts: wallet.unified_accounts().account_metadata.len(),
            sapling_spending: wallet.sapling_keys().keypairs().count(),
            sapling_standalone: imported_sapling_standalone,
            sapling_viewonly: wallet.sapling_extended_full_viewing_keys().len(),
            transparent_keys: imported_transparent_keys,
            watchonly_pubkeys: imported_watchonly_pubkeys,
            watchonly_scripts: imported_watchonly_scripts,
            skipped_uncompressed_pubkeys,
            skipped_p2pkh_address_only,
            skipped_p2sh_address_only,
            skipped_nonstandard,
            skipped_unsupported_scripts,
            err_malformed_pubkeys: skipped_malformed_pubkeys,
            err_unparseable_scripts: skipped_unparseable_scripts,
            dropped_sprout_keys: wallet.sprout_keys().map_or(0, |k| k.keypairs().count()),
            dropped_wkey_keys: wallet.wallet_keys().map_or(0, |k| k.keypairs().count()),
            unified_address_meta_dropped: wallet.unified_accounts().address_metadata.len(),
            unparsed_records,
        };
        summary.print();

        Ok(())
    }
}

/// Human-readable tally of what `migrate-zcashd-wallet` imported, skipped, or
/// could not migrate. Printed at the end of migration so the operator can see
/// exactly which key material did and did not make it into the Zallet wallet,
/// and is reminded to retain their original `wallet.dat`.
struct MigrationSummary {
    mnemonic_seed: bool,
    legacy_hd_seed: bool,
    unified_accounts: usize,
    sapling_spending: usize,
    sapling_standalone: usize,
    sapling_viewonly: usize,
    transparent_keys: usize,
    watchonly_pubkeys: usize,
    watchonly_scripts: usize,
    // Recognized but not representable in Zallet yet.
    skipped_uncompressed_pubkeys: usize,
    skipped_p2pkh_address_only: usize,
    skipped_p2sh_address_only: usize,
    skipped_nonstandard: usize,
    skipped_unsupported_scripts: usize,
    // Malformed / unparseable records.
    err_malformed_pubkeys: usize,
    err_unparseable_scripts: usize,
    // Spend authority present in wallet.dat but not migrated; funds controlled
    // by it can only be spent from the original wallet.dat.
    dropped_sprout_keys: usize,
    dropped_wkey_keys: usize,
    // Previously-issued unified address metadata that was not migrated. Not
    // spend authority, but its loss can cause address reuse and untracked
    // transparent receivers (see the note printed below).
    unified_address_meta_dropped: usize,
    /// All wallet.dat record types the parser could not interpret, keyed by the
    /// zcashd record name (e.g. `ckey`, `csapzkey`, `czkey`).
    unparsed_records: BTreeMap<String, usize>,
}

/// Maps an unparsed zcashd record name to a human description when that record
/// type carries spend authority (and therefore represents potential fund loss).
fn dropped_spend_authority_label(keyname: &str) -> Option<&'static str> {
    match keyname {
        "ckey" => Some("encrypted transparent spending keys (ckey)"),
        "csapzkey" => Some("encrypted Sapling spending keys (csapzkey)"),
        "czkey" => Some("encrypted Sprout spending keys (czkey)"),
        "chdseed" => Some("encrypted legacy HD seed (chdseed)"),
        "cmnemonicphrase" => Some("encrypted mnemonic phrase (cmnemonicphrase)"),
        "mkey" => Some("wallet master encryption key (mkey)"),
        _ => None,
    }
}

impl MigrationSummary {
    fn any_dropped_spend_authority(&self) -> bool {
        self.dropped_sprout_keys > 0
            || self.dropped_wkey_keys > 0
            || self
                .unparsed_records
                .keys()
                .any(|k| dropped_spend_authority_label(k).is_some())
    }

    /// Prints the migration summary and an always-on reminder to back up both
    /// the original `wallet.dat` and the new Zallet wallet (`wallet.db` plus its
    /// age encryption identity file).
    fn print(&self) {
        let yn = |b: bool| if b { "yes" } else { "no" };
        let bar = "=".repeat(72);

        println!("\n{bar}");
        println!("zcashd -> Zallet migration summary");
        println!("{bar}");
        println!("Imported into the Zallet wallet (wallet.db):");
        println!(
            "  mnemonic seed ..................... {}",
            yn(self.mnemonic_seed)
        );
        println!(
            "  legacy HD seed .................... {}",
            yn(self.legacy_hd_seed)
        );
        println!(
            "  unified accounts ................. {}",
            self.unified_accounts
        );
        println!(
            "  Sapling spending keys ............ {} (standalone imported: {})",
            self.sapling_spending, self.sapling_standalone,
        );
        println!(
            "  Sapling view-only keys ........... {}",
            self.sapling_viewonly
        );
        println!(
            "  transparent spending keys ........ {}",
            self.transparent_keys
        );
        println!(
            "  watch-only transparent pubkeys ... {}",
            self.watchonly_pubkeys
        );
        println!(
            "  watch-only redeem scripts ........ {}",
            self.watchonly_scripts
        );

        let skipped_total = self.skipped_uncompressed_pubkeys
            + self.skipped_p2pkh_address_only
            + self.skipped_p2sh_address_only
            + self.skipped_nonstandard
            + self.skipped_unsupported_scripts;
        if skipped_total > 0 {
            println!("\nSkipped (recognized but not migratable yet):");
            if self.skipped_uncompressed_pubkeys > 0 {
                println!(
                    "  uncompressed watch-only pubkeys .. {}",
                    self.skipped_uncompressed_pubkeys
                );
            }
            if self.skipped_p2pkh_address_only > 0 {
                println!(
                    "  P2PKH address-only watch entries . {}",
                    self.skipped_p2pkh_address_only
                );
            }
            if self.skipped_p2sh_address_only > 0 {
                println!(
                    "  P2SH address-only watch entries .. {}",
                    self.skipped_p2sh_address_only
                );
            }
            if self.skipped_nonstandard > 0 {
                println!(
                    "  non-standard watch scripts ....... {}",
                    self.skipped_nonstandard
                );
            }
            if self.skipped_unsupported_scripts > 0 {
                println!(
                    "  unsupported redeem scripts ....... {}",
                    self.skipped_unsupported_scripts
                );
            }
        }

        let err_total = self.err_malformed_pubkeys + self.err_unparseable_scripts;
        if err_total > 0 {
            println!("\nErrors (malformed / unparseable, not migrated):");
            if self.err_malformed_pubkeys > 0 {
                println!(
                    "  malformed watch-only pubkeys ..... {}",
                    self.err_malformed_pubkeys
                );
            }
            if self.err_unparseable_scripts > 0 {
                println!(
                    "  unparseable redeem scripts ....... {}",
                    self.err_unparseable_scripts
                );
            }
        }

        // Record types the parser did not interpret that are NOT spend authority
        // (informational; e.g. address book / metadata records).
        let other_unparsed: Vec<(&String, &usize)> = self
            .unparsed_records
            .iter()
            .filter(|(k, _)| dropped_spend_authority_label(k).is_none())
            .collect();
        if !other_unparsed.is_empty() {
            println!("\nOther wallet.dat records not migrated (not key material):");
            for (keyname, count) in other_unparsed {
                println!("  {keyname} ....... {count}");
            }
        }

        if self.unified_address_meta_dropped > 0 {
            println!(
                "\nNote: {} previously-issued unified address(es) recorded by zcashd were",
                self.unified_address_meta_dropped,
            );
            println!("not migrated. Newly generated addresses may repeat ones zcashd already");
            println!(
                "handed out, and payments to some old transparent receivers may not be tracked."
            );
        }

        if self.any_dropped_spend_authority() {
            let warnbar = "!".repeat(72);
            println!("\n{warnbar}");
            println!("WARNING: SPEND AUTHORITY WAS NOT MIGRATED");
            println!("{warnbar}");
            println!("The following key material is present in your zcashd wallet.dat but was");
            println!("NOT imported into Zallet. Funds controlled by it can ONLY be spent using");
            println!("your original zcashd wallet.dat:");
            if self.dropped_sprout_keys > 0 {
                println!(
                    "  Sprout spending keys ............. {} (Zallet does not support Sprout)",
                    self.dropped_sprout_keys,
                );
            }
            if self.dropped_wkey_keys > 0 {
                println!(
                    "  legacy `wkey` transparent keys ... {}",
                    self.dropped_wkey_keys
                );
            }
            for (keyname, count) in &self.unparsed_records {
                if let Some(label) = dropped_spend_authority_label(keyname) {
                    println!("  {label} ... {count}");
                }
            }
            println!("\nIf your zcashd wallet was encrypted, its spending keys are stored in");
            println!("encrypted `ckey`/`csapzkey`/`czkey` records that this migration cannot yet");
            println!("read, and were NOT migrated.");
        }

        // Always remind the operator about backups, even for a clean run: this
        // migration is alpha and does not cover every zcashd record type, and the
        // Zallet wallet.db itself holds spend authority that no seed phrase can
        // regenerate.
        let starbar = "*".repeat(72);
        println!("\n{starbar}");
        println!("BACK UP YOUR WALLETS — this is not optional");
        println!("{starbar}");
        println!("1. Your ORIGINAL zcashd wallet.dat:");
        println!("   * Do NOT delete or discard it. Keep a secure backup (copying it to");
        println!("     safe storage is fine and encouraged).");
        println!("   * This migration is alpha and does not import every kind of key. For");
        println!("     any key that was NOT migrated, wallet.dat is the ONLY copy: that key");
        println!("     material was never written to the Zallet wallet.db.");
        println!("   * If you lose wallet.dat, funds whose keys were not migrated are");
        println!("     PERMANENTLY UNRECOVERABLE, even if your Zallet wallet.db is intact.");
        println!("2. Your NEW Zallet wallet:");
        println!("   * The Zallet wallet.db holds spending keys that CANNOT be recovered");
        println!("     from any seed phrase (standalone imported keys, legacy seeds, and");
        println!("     migrated transparent keys). `zallet export-mnemonic` does NOT back");
        println!("     these up.");
        println!("   * There is currently no backup RPC or command. To back up the Zallet");
        println!("     wallet, make a secure copy of BOTH:");
        println!("       - the wallet database file (wallet.db in your datadir), and");
        println!("       - the age encryption identity file (the file named by the");
        println!("         keystore.encryption_identity config option). wallet.db is");
        println!("         encrypted to it and cannot be decrypted without it (plus its");
        println!("         passphrase, if the identity is passphrase-encrypted).");
        println!("   * Losing either the wallet.db or its identity file means losing access");
        println!("     to every key held only in the Zallet wallet.");
        println!("{starbar}\n");

        if self.any_dropped_spend_authority() {
            warn!(
                "Migration did not import all spend authority from wallet.dat; keep a \
                 secure backup of the original wallet.dat (see summary above)."
            );
        }
    }
}

impl Runnable for MigrateZcashdWalletCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}

#[derive(Debug)]
pub(crate) enum ZewifError {
    BdbDump,
    ZcashdDump,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum MigrateError {
    Wrapped(Error),
    Zewif {
        error_type: ZewifError,
        wallet_path: PathBuf,
        error: anyhow::Error,
    },
    SeedNotAvailable,
    MnemonicInvalid(bip0039::Error),
    KeyError(secp256k1::Error),
    NetworkMismatch {
        wallet_network: zewif::Network,
        db_network: NetworkType,
    },
    NetworkNotSupported(NetworkType),
    Database(SqliteClientError),
    Tree(ShardTreeError<zcash_client_sqlite::wallet::commitment_tree::Error>),
    Io(std::io::Error),
    KeyDerivation(DerivationError),
    HdPath(PathParseError),
    AccountIdInvalid(u32),
    MultiImportDisabled,
    DuplicateImport(SeedFingerprint),
}

impl From<MigrateError> for Error {
    fn from(value: MigrateError) -> Self {
        match value {
            MigrateError::Wrapped(e) => e,
            MigrateError::Zewif {
                error_type,
                wallet_path,
                error,
            } => Error::from(match error_type {
                ZewifError::BdbDump => ErrorKind::Generic.context(fl!(
                    "err-migrate-wallet-bdb-parse",
                    path = wallet_path.to_str(),
                    err = error.to_string()
                )),
                ZewifError::ZcashdDump => ErrorKind::Generic.context(fl!(
                    "err-migrate-wallet-db-dump",
                    path = wallet_path.to_str(),
                    err = error.to_string()
                )),
            }),
            MigrateError::SeedNotAvailable => {
                Error::from(ErrorKind::Generic.context(fl!("err-migrate-wallet-seed-absent")))
            }
            MigrateError::MnemonicInvalid(error) => Error::from(ErrorKind::Generic.context(fl!(
                "err-migrate-wallet-invalid-mnemonic",
                err = error.to_string()
            ))),
            MigrateError::KeyError(error) => Error::from(ErrorKind::Generic.context(fl!(
                "err-migrate-wallet-key-decoding",
                err = error.to_string()
            ))),
            MigrateError::NetworkMismatch {
                wallet_network,
                db_network,
            } => Error::from(ErrorKind::Generic.context(fl!(
                "err-migrate-wallet-network-mismatch",
                wallet_network = String::from(wallet_network),
                zallet_network = match db_network {
                    NetworkType::Main => "main",
                    NetworkType::Test => "test",
                    NetworkType::Regtest => "regtest",
                }
            ))),
            MigrateError::NetworkNotSupported(_) => {
                Error::from(ErrorKind::Generic.context(fl!("err-migrate-wallet-regtest")))
            }
            MigrateError::Database(sqlite_client_error) => {
                Error::from(ErrorKind::Generic.context(fl!(
                    "err-migrate-wallet-storage",
                    err = sqlite_client_error.to_string()
                )))
            }
            MigrateError::Tree(e) => Error::from(
                ErrorKind::Generic
                    .context(fl!("err-migrate-wallet-data-parse", err = e.to_string())),
            ),
            MigrateError::Io(e) => Error::from(
                ErrorKind::Generic
                    .context(fl!("err-migrate-wallet-data-parse", err = e.to_string())),
            ),
            MigrateError::KeyDerivation(e) => Error::from(
                ErrorKind::Generic.context(fl!("err-migrate-wallet-key-data", err = e.to_string())),
            ),
            MigrateError::HdPath(err) => Error::from(ErrorKind::Generic.context(fl!(
                "err-migrate-wallet-data-parse",
                err = format!("{:?}", err)
            ))),
            MigrateError::AccountIdInvalid(id) => Error::from(ErrorKind::Generic.context(fl!(
                "err-migrate-wallet-invalid-account-id",
                account_id = id
            ))),
            MigrateError::MultiImportDisabled => Error::from(
                ErrorKind::Generic.context(fl!("err-migrate-wallet-multi-import-disabled")),
            ),
            MigrateError::DuplicateImport(seed_fingerprint) => {
                Error::from(ErrorKind::Generic.context(fl!(
                    "err-migrate-wallet-duplicate-import",
                    seed_fp = format!("{}", seed_fingerprint)
                )))
            }
        }
    }
}

impl From<ShardTreeError<zcash_client_sqlite::wallet::commitment_tree::Error>> for MigrateError {
    fn from(e: ShardTreeError<zcash_client_sqlite::wallet::commitment_tree::Error>) -> Self {
        Self::Tree(e)
    }
}

impl From<SqliteClientError> for MigrateError {
    fn from(e: SqliteClientError) -> Self {
        Self::Database(e)
    }
}

impl From<bip0039::Error> for MigrateError {
    fn from(value: bip0039::Error) -> Self {
        Self::MnemonicInvalid(value)
    }
}

impl From<Error> for MigrateError {
    fn from(value: Error) -> Self {
        MigrateError::Wrapped(value)
    }
}

impl From<abscissa_core::error::Context<ErrorKind>> for MigrateError {
    fn from(value: abscissa_core::error::Context<ErrorKind>) -> Self {
        MigrateError::Wrapped(value.into())
    }
}

impl From<ChainError> for MigrateError {
    fn from(value: ChainError) -> Self {
        MigrateError::Wrapped(value.into())
    }
}

impl From<std::io::Error> for MigrateError {
    fn from(value: std::io::Error) -> Self {
        MigrateError::Io(value)
    }
}

impl From<DerivationError> for MigrateError {
    fn from(value: DerivationError) -> Self {
        MigrateError::KeyDerivation(value)
    }
}

impl From<PathParseError> for MigrateError {
    fn from(value: PathParseError) -> Self {
        MigrateError::HdPath(value)
    }
}

impl From<secp256k1::Error> for MigrateError {
    fn from(value: secp256k1::Error) -> Self {
        MigrateError::KeyError(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_summary() -> MigrationSummary {
        MigrationSummary {
            mnemonic_seed: false,
            legacy_hd_seed: false,
            unified_accounts: 0,
            sapling_spending: 0,
            sapling_standalone: 0,
            sapling_viewonly: 0,
            transparent_keys: 0,
            watchonly_pubkeys: 0,
            watchonly_scripts: 0,
            skipped_uncompressed_pubkeys: 0,
            skipped_p2pkh_address_only: 0,
            skipped_p2sh_address_only: 0,
            skipped_nonstandard: 0,
            skipped_unsupported_scripts: 0,
            err_malformed_pubkeys: 0,
            err_unparseable_scripts: 0,
            dropped_sprout_keys: 0,
            dropped_wkey_keys: 0,
            unified_address_meta_dropped: 0,
            unparsed_records: BTreeMap::new(),
        }
    }

    #[test]
    fn encrypted_and_master_records_are_flagged_as_spend_authority() {
        // These are the record types that an encrypted zcashd wallet.dat stores
        // and that the parser cannot yet interpret; each must be surfaced.
        for keyname in [
            "ckey",
            "csapzkey",
            "czkey",
            "chdseed",
            "cmnemonicphrase",
            "mkey",
        ] {
            assert!(
                dropped_spend_authority_label(keyname).is_some(),
                "expected `{keyname}` to be flagged as dropped spend authority",
            );
        }
    }

    #[test]
    fn benign_records_are_not_flagged_as_spend_authority() {
        for keyname in ["bestblock", "version", "name", "purpose", "destdata"] {
            assert!(dropped_spend_authority_label(keyname).is_none());
        }
    }

    #[test]
    fn clean_migration_reports_no_dropped_spend_authority() {
        assert!(!empty_summary().any_dropped_spend_authority());
    }

    #[test]
    fn dropped_sprout_or_wkey_keys_flag_spend_authority() {
        let mut sprout = empty_summary();
        sprout.dropped_sprout_keys = 1;
        assert!(sprout.any_dropped_spend_authority());

        let mut wkey = empty_summary();
        wkey.dropped_wkey_keys = 3;
        assert!(wkey.any_dropped_spend_authority());
    }

    #[test]
    fn unparsed_encrypted_record_flags_spend_authority() {
        let mut summary = empty_summary();
        summary.unparsed_records.insert("csapzkey".to_string(), 2);
        assert!(summary.any_dropped_spend_authority());
    }

    #[test]
    fn unparsed_benign_record_does_not_flag_spend_authority() {
        let mut summary = empty_summary();
        summary.unparsed_records.insert("destdata".to_string(), 5);
        assert!(!summary.any_dropped_spend_authority());
    }
}
