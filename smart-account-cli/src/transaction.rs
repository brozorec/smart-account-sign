//! Manual transaction building and submission

use anyhow::Result;
use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};
use stellar_rpc_client::Client;
use stellar_xdr::curr::{
    DecoratedSignature, Hash, HostFunction, InvokeHostFunctionOp, Limits, Memo, MuxedAccount,
    Operation, OperationBody, Preconditions, ReadXdr, SequenceNumber, Signature, SignatureHint,
    SorobanAuthorizationEntry, SorobanTransactionData, Transaction, TransactionEnvelope,
    TransactionExt, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

/// Build and send transaction manually (without relayer)
pub async fn send_transaction_manually(
    client: &Client,
    source_account: &str,
    source_secret: &str,
    host_function: &HostFunction,
    auth_entries: Vec<SorobanAuthorizationEntry>,
) -> Result<()> {
    eprintln!("Building transaction manually...");
    eprintln!("  Source account: {}", source_account);

    // Parse source keypair
    let source_keypair = stellar_strkey::ed25519::PrivateKey::from_string(source_secret)?;
    let source_public = stellar_strkey::ed25519::PublicKey::from_string(source_account)?;

    // Get account details from RPC
    let account_response = client.get_account(source_account).await?;
    let sequence = account_response.seq_num.0;

    // Build initial transaction for simulation
    let base_fee = 100u32;
    let mut tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(source_public.0)),
        fee: base_fee,
        seq_num: SequenceNumber(sequence + 1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: host_function.clone(),
                auth: auth_entries.clone().try_into()?,
            }),
        }]
        .try_into()?,
        ext: TransactionExt::V0,
    };

    let simulate_envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: VecM::default(),
    });

    // Simulate to get resource fees
    let simulate_result = client
        .simulate_transaction_envelope(&simulate_envelope, None)
        .await?;

    if let Some(error) = simulate_result.error {
        anyhow::bail!("Simulation failed: {}", error);
    }

    // Parse transaction data from base64 string
    let transaction_data_str = &simulate_result.transaction_data;
    let transaction_data_bytes =
        base64::engine::general_purpose::STANDARD.decode(transaction_data_str)?;
    let transaction_data =
        SorobanTransactionData::from_xdr(&transaction_data_bytes, Limits::none())?;

    let min_resource_fee = simulate_result.min_resource_fee;
    let total_fee = base_fee + min_resource_fee as u32;

    // Build final transaction with proper fees and soroban data
    tx.fee = total_fee;
    tx.ext = TransactionExt::V1(transaction_data);

    // Sign transaction
    let network_passphrase = client.get_network().await?.passphrase;
    let network_id = Sha256::digest(network_passphrase.as_bytes());
    let tx_hash = Sha256::digest(
        TransactionSignaturePayload {
            network_id: Hash(network_id.into()),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        }
        .to_xdr(Limits::none())?,
    );

    let signing_key = SigningKey::from_bytes(&source_keypair.0);
    let signature = signing_key.sign(&tx_hash);

    let decorated_signature = DecoratedSignature {
        hint: SignatureHint(source_public.0[28..32].try_into()?),
        signature: Signature(signature.to_bytes().try_into()?),
    };

    let signed_envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![decorated_signature].try_into()?,
    });

    // Send transaction
    eprintln!("\nSending transaction...");
    let send_result = client.send_transaction(&signed_envelope).await?;

    eprintln!("\n✅ Transaction sent successfully!");
    eprintln!("  Transaction hash: {}", hex::encode(send_result.0));

    // Also output XDR for reference
    //eprintln!("\nTransaction XDR (base64):");
    //let xdr_base64 =
    //base64::engine::general_purpose::STANDARD.encode(signed_envelope.to_xdr(Limits::none())?);
    //println!("{}", xdr_base64);

    Ok(())
}
