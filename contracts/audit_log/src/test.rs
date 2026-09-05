#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Ledger, Env, String};

#[test]
fn test_log_and_retrieve_evidence() {
    let env = Env::default();
    let contract_id = env.register_contract(None, AuditLogContract);
    let client = AuditLogContractClient::new(&env, &contract_id);

    let idx = client.log_evidence(
        &String::from_str(&env, "ENTITY_EXTRACTED"),
        &String::from_str(&env, "f73f56a1811d39974a27b2fbd35dbea50e216627ad92d5c0fb13f674c758724"),
    );
    assert_eq!(idx, 0);
    assert_eq!(client.chain_length(), 1);

    let block = client.get_block(&0).unwrap();
    assert_eq!(block.event_type, String::from_str(&env, "ENTITY_EXTRACTED"));
}

#[test]
fn test_chain_grows_append_only() {
    let env = Env::default();
    let contract_id = env.register_contract(None, AuditLogContract);
    let client = AuditLogContractClient::new(&env, &contract_id);

    for i in 0..5 {
        client.log_evidence(
            &String::from_str(&env, "ALERT_RAISED"),
            &String::from_str(&env, "hash_placeholder"),
        );
    }
    assert_eq!(client.chain_length(), 5);
}
