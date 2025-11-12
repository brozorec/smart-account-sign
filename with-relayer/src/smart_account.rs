use anyhow::{Context, Result};
use prettytable::{Cell, Row, Table};
use serde::Serialize;
use std::io::{self, Write};
use stellar_rpc_client::Client;
use stellar_xdr::curr::{
    ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Limits, Memo,
    MuxedAccount, Operation, OperationBody, Preconditions, ReadXdr, ScAddress, ScBytes, ScMap,
    ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SequenceNumber, StringM, Transaction,
    TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM,
};

// Field name constants for type-safe parsing
const FIELD_CONTEXT_TYPE: &str = "context_type";
const FIELD_ID: &str = "id";
const FIELD_NAME: &str = "name";
const FIELD_POLICIES: &str = "policies";
const FIELD_SIGNERS: &str = "signers";
const FIELD_VALID_UNTIL: &str = "valid_until";

#[derive(Serialize, Clone, Debug)]
pub struct ContextRule {
    pub context_type: Option<String>,
    pub id: Option<u32>,
    pub name: Option<String>,
    pub policies: Vec<ContractId>,
    pub signers: Vec<Signer>,
    pub valid_until: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Signer {
    pub signer_type: StringM<32>,
    pub contract_id: ContractId,
    pub public_key: ScBytes,
    pub signer_vec: VecM<ScVal>,
}

/// Fetches all context rules from a smart account and displays them in a table
pub async fn get_context_rules_table(
    client: &Client,
    account_addr: &str,
) -> Result<Vec<ContextRule>> {
    let contract_addr =
        stellar_strkey::Contract::from_string(account_addr).context("Invalid smart account ID")?;
    let contract_address = ScAddress::Contract(ContractId(Hash(contract_addr.0)));

    let mut rules = Vec::new();
    let mut rule_id = 0u32;

    eprintln!("Fetching context rules from smart account...");

    loop {
        // Build invoke args for get_context_rule
        let function_name = ScSymbol("get_context_rule".try_into()?);
        let args: VecM<ScVal> = vec![ScVal::U32(rule_id)].try_into()?;

        let invoke_args = InvokeContractArgs {
            contract_address: contract_address.clone(),
            function_name,
            args,
        };

        // Build a minimal transaction envelope for simulation
        let host_function = HostFunction::InvokeContract(invoke_args);

        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function,
                auth: VecM::default(),
            }),
        };

        // Use a dummy source account for simulation
        let source = MuxedAccount::Ed25519(Uint256([0; 32]));

        let tx = Transaction {
            source_account: source,
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op].try_into()?,
            ext: TransactionExt::V0,
        };

        let tx_envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });

        // Simulate the transaction
        match client
            .simulate_transaction_envelope(&tx_envelope, None)
            .await
        {
            Ok(response) => {
                let results = response.results;
                if let Some(result_raw) = results.first() {
                    // Parse the XDR result
                    if let Ok(ScVal::Map(Some(scmap))) =
                        ScVal::from_xdr_base64(&result_raw.xdr, Limits::none())
                    {
                        let rule = extract_values(&scmap);
                        rules.push(rule);
                        rule_id += 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            Err(_) => {
                // No more rules found or error occurred
                break;
            }
        }
    }

    if rules.is_empty() {
        anyhow::bail!("No context rules available for this smart account");
    } else {
        display_rules_table(&rules, account_addr);
    }

    Ok(rules)
}

fn display_rules_table(rules: &[ContextRule], account_addr: &str) {
    let mut table = Table::new();

    table.add_row(Row::new(vec![
        Cell::new("ID"),
        Cell::new("Name"),
        Cell::new("Context Type"),
        Cell::new("Signers"),
        Cell::new("Policies"),
        Cell::new("Valid Until"),
    ]));

    for rule in rules {
        let id_str = rule
            .id
            .map(|i| i.to_string())
            .unwrap_or_else(|| "N/A".to_string());
        let name_str = rule.name.clone().unwrap_or_else(|| "N/A".to_string());
        let context_type_str = rule
            .context_type
            .clone()
            .unwrap_or_else(|| "N/A".to_string());

        let signers_str = if rule.signers.is_empty() {
            "None".to_string()
        } else {
            let mut signer_lines = Vec::new();
            for signer in rule.signers.iter() {
                let signer_type = signer.signer_type.to_string();

                if signer_type == "External" {
                    signer_lines.push(format!(
                        "• External\n  Verifier: {}\n  PubKey: {}",
                        stellar_strkey::Contract(signer.contract_id.0.clone().into()).to_string(),
                        hex::encode(&signer.public_key.0)
                    ));
                } else {
                    signer_lines.push(format!(
                        "• Delegated\n  Address: {}",
                        stellar_strkey::Contract(signer.contract_id.0.clone().into()).to_string()
                    ));
                }
            }
            signer_lines.join("\n")
        };

        let policies_str = if rule.policies.is_empty() {
            "None".to_string()
        } else {
            rule.policies
                .iter()
                .map(|policy| {
                    format!(
                        "• {}",
                        stellar_strkey::Contract(policy.0.clone().into()).to_string()
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        let valid_until_str = rule
            .valid_until
            .clone()
            .unwrap_or_else(|| "None".to_string());

        table.add_row(Row::new(vec![
            Cell::new(&id_str),
            Cell::new(&name_str),
            Cell::new(&context_type_str),
            Cell::new(&signers_str),
            Cell::new(&policies_str),
            Cell::new(&valid_until_str),
        ]));
    }

    eprintln!("\nContext Rules for Smart Account: {}\n", account_addr);
    table.printstd();
    eprintln!();
}

/// Prompt user to select a context rule
pub fn prompt_rule_selection(rules: &[ContextRule]) -> Result<ContextRule> {
    if rules.is_empty() {
        anyhow::bail!("No context rules available");
    }

    eprint!("Enter the rule ID to use: ");
    io::stderr().flush()?;
    let mut rule_id_input = String::new();
    io::stdin().read_line(&mut rule_id_input)?;
    let selected_rule_id: u32 = rule_id_input.trim().parse().context("Invalid rule ID")?;

    rules
        .iter()
        .find(|r| r.id == Some(selected_rule_id))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Rule with ID {} not found", selected_rule_id))
}

fn extract_values(scmap: &ScMap) -> ContextRule {
    let mut context_type = None;
    let mut id = None;
    let mut name = None;
    let mut policies = vec![];
    let mut signers = vec![];
    let mut valid_until = None;

    for ScMapEntry { key, val } in scmap.iter() {
        let ScVal::Symbol(ScSymbol(sym)) = key else {
            continue;
        };

        match sym.to_string().as_str() {
            FIELD_CONTEXT_TYPE => {
                context_type = match val {
                    ScVal::Vec(Some(ScVec(values))) => {
                        values.as_slice().first().and_then(|v| match v {
                            ScVal::Symbol(ScSymbol(s)) => Some(s.to_string()),
                            _ => None,
                        })
                    }
                    _ => None,
                };
            }
            FIELD_ID => {
                id = match val {
                    ScVal::U32(v) => Some(*v),
                    _ => None,
                };
            }
            FIELD_NAME => {
                name = match val {
                    ScVal::String(ScString(v)) => Some(String::from_utf8_lossy(v).to_string()),
                    _ => None,
                };
            }
            FIELD_POLICIES => {
                if let ScVal::Vec(Some(ScVec(vec))) = val {
                    policies = vec
                        .as_slice()
                        .iter()
                        .filter_map(|policy| match policy {
                            ScVal::Address(ScAddress::Contract(contract)) => Some(contract.clone()),
                            _ => None,
                        })
                        .collect();
                }
            }
            FIELD_SIGNERS => {
                if let ScVal::Vec(Some(ScVec(vec_outer))) = val {
                    signers = vec_outer
                        .as_slice()
                        .iter()
                        .filter_map(|signer_vec| {
                            let ScVal::Vec(Some(ScVec(inner))) = signer_vec else {
                                return None;
                            };

                            let ScVal::Symbol(ScSymbol(signer_type)) = &inner.as_slice()[0] else {
                                return None;
                            };

                            let contract_id = match inner.as_slice()[1].clone() {
                                ScVal::Address(ScAddress::Contract(id)) => id,
                                // TODO: G-accounts
                                //ScVal::Address(ScAddress::Account(id)) => id,
                                _ => return None,
                            };

                            let ScVal::Bytes(public_key) = &inner.as_slice()[2] else {
                                return None;
                            };

                            Some(Signer {
                                signer_type: signer_type.clone(),
                                contract_id,
                                public_key: public_key.clone(),
                                signer_vec: inner.clone(),
                            })
                        })
                        .collect();
                }
            }
            FIELD_VALID_UNTIL => {
                valid_until = Some(format!("{:?}", val));
            }
            _ => {}
        }
    }

    ContextRule {
        context_type,
        id,
        name,
        policies,
        signers,
        valid_until,
    }
}
