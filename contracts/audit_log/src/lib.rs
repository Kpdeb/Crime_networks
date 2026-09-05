//! Evidence Audit Log — Soroban Smart Contract
//!
//! Stores a tamper-proof, append-only log of evidence hashes on the
//! Stellar network. Each time the off-chain NLP/graph pipeline
//! extracts a new entity, relationship, or raises an alert, its hash
//! is committed here. Because the ledger is public and decentralized,
//! no single party (including investigators or the department running
//! this system) can silently alter past records — any change to the
//! logged data would produce a different hash and no longer match
//! the on-chain commitment.
//!
//! This complements the local hash-chain simulation in
//! src/blockchain/audit_log.py — that Python version is used for the
//! fast local prototype/demo; this contract is the real on-chain
//! version intended for production deployment on Stellar (Soroban).
//!
//! Deploy with the Soroban CLI, e.g.:
//!   soroban contract build
//!   soroban contract deploy --wasm target/.../audit_log.wasm --network testnet

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Env, String, Symbol, Vec, symbol_short};

#[contracttype]
#[derive(Clone)]
pub struct EvidenceBlock {
    pub index: u64,
    pub event_type: String,
    pub evidence_hash: String,   // SHA-256 hash of the off-chain evidence payload
    pub timestamp: u64,
}

const CHAIN: Symbol = symbol_short!("CHAIN");

#[contract]
pub struct AuditLogContract;

#[contractimpl]
impl AuditLogContract {
    /// Append a new evidence block to the on-chain log.
    /// Only the hash of the evidence is stored on-chain (not the raw
    /// sensitive data itself) — this keeps case data off the public
    /// ledger while still proving it hasn't been altered since logging.
    pub fn log_evidence(env: Env, event_type: String, evidence_hash: String) -> u64 {
        let mut chain: Vec<EvidenceBlock> = env
            .storage()
            .instance()
            .get(&CHAIN)
            .unwrap_or(Vec::new(&env));

        let block = EvidenceBlock {
            index: chain.len() as u64,
            event_type,
            evidence_hash,
            timestamp: env.ledger().timestamp(),
        };

        chain.push_back(block);
        env.storage().instance().set(&CHAIN, &chain);

        chain.len() as u64 - 1
    }

    /// Retrieve the full on-chain evidence log for verification/audit.
    pub fn get_chain(env: Env) -> Vec<EvidenceBlock> {
        env.storage()
            .instance()
            .get(&CHAIN)
            .unwrap_or(Vec::new(&env))
    }

    /// Retrieve a single block by index, e.g. for verifying one piece of evidence.
    pub fn get_block(env: Env, index: u64) -> Option<EvidenceBlock> {
        let chain: Vec<EvidenceBlock> = env
            .storage()
            .instance()
            .get(&CHAIN)
            .unwrap_or(Vec::new(&env));
        chain.get(index as u32)
    }

    /// Total number of evidence blocks logged so far.
    pub fn chain_length(env: Env) -> u64 {
        let chain: Vec<EvidenceBlock> = env
            .storage()
            .instance()
            .get(&CHAIN)
            .unwrap_or(Vec::new(&env));
        chain.len() as u64
    }
}

mod test;
