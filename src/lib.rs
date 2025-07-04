use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt}; // For reading/writing bytes in little-endian format
use hex;
use serde::{Deserialize, Serialize}; // For JSON serialization/deserialization
use std::fmt; // For the Display trait
use std::io::{Cursor, Read, Write}; // For byte operations and the Write trait
use std::ops::Deref; // For the Deref trait // For hex encoding/decoding of Txid

// The `CompactSize` struct represents a variable-length integer used in Bitcoin's serialization.
// It can encode numbers from 0 up to 2^64 - 1, using 1, 3, 5, or 9 bytes depending on the value.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CompactSize {
    pub value: u64,
}

// Custom error type for Bitcoin-related serialization/deserialization issues.
#[derive(Debug)]
pub enum BitcoinError {
    InsufficientBytes,           // Not enough bytes provided for deserialization.
    InvalidFormat,               // Data format is not as expected.
    HexError(hex::FromHexError), // Error from hex decoding.
    IoError(std::io::Error),     // General I/O error during byte operations.
}

// Implement `From` traits for easier error conversion.
impl From<hex::FromHexError> for BitcoinError {
    fn from(err: hex::FromHexError) -> Self {
        BitcoinError::HexError(err)
    }
}

impl From<std::io::Error> for BitcoinError {
    fn from(err: std::io::Error) -> Self {
        BitcoinError::IoError(err)
    }
}

impl CompactSize {
    // Creates a new `CompactSize` instance from a `u64` value.
    pub fn new(value: u64) -> Self {
        CompactSize { value }
    }

    // Serializes the `CompactSize` value into a `Vec<u8>` according to Bitcoin's rules.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        if self.value < 0xFD {
            // If value is less than 0xFD (253), it's encoded as a single byte.
            bytes.write_u8(self.value as u8).unwrap();
        } else if self.value <= 0xFFFF {
            // If value is between 0xFD and 0xFFFF (65535), it's prefixed with 0xFD, then a 2-byte little-endian u16.
            bytes.write_u8(0xFD).unwrap();
            bytes.write_u16::<LittleEndian>(self.value as u16).unwrap();
        } else if self.value <= 0xFFFFFFFF {
            // If value is between 0x10000 and 0xFFFFFFFF (4294967295), it's prefixed with 0xFE, then a 4-byte little-endian u32.
            bytes.write_u8(0xFE).unwrap();
            bytes.write_u32::<LittleEndian>(self.value as u32).unwrap();
        } else {
            // If value is greater than 0xFFFFFFFF, it's prefixed with 0xFF, then an 8-byte little-endian u64.
            bytes.write_u8(0xFF).unwrap();
            bytes.write_u64::<LittleEndian>(self.value).unwrap();
        }
        bytes
    }

    // Deserializes a `CompactSize` from a byte slice, returning the decoded `CompactSize`
    // and the number of bytes consumed.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // Ensure there's at least one byte to read the prefix.
        if bytes.is_empty() {
            return Err(BitcoinError::InsufficientBytes);
        }

        let mut cursor = Cursor::new(bytes);
        let prefix = cursor.read_u8()?;
        let value: u64;
        let consumed_bytes: usize;

        if prefix < 0xFD {
            // Single byte value.
            value = prefix as u64;
            consumed_bytes = 1;
        } else if prefix == 0xFD {
            // 2-byte u16 value.
            if bytes.len() < 3 {
                return Err(BitcoinError::InsufficientBytes);
            }
            value = cursor.read_u16::<LittleEndian>()? as u64;
            consumed_bytes = 3;
        } else if prefix == 0xFE {
            // 4-byte u32 value.
            if bytes.len() < 5 {
                return Err(BitcoinError::InsufficientBytes);
            }
            value = cursor.read_u32::<LittleEndian>()? as u64;
            consumed_bytes = 5;
        } else {
            // prefix == 0xFF
            // 8-byte u64 value.
            if bytes.len() < 9 {
                return Err(BitcoinError::InsufficientBytes);
            }
            value = cursor.read_u64::<LittleEndian>()?;
            consumed_bytes = 9;
        }

        Ok((CompactSize::new(value), consumed_bytes))
    }
}

// `Txid` represents a Bitcoin transaction ID, which is a 32-byte hash.
// It is wrapped in a tuple struct for type safety and to implement custom serialization/deserialization.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Txid(pub [u8; 32]);

impl Serialize for Txid {
    // Serializes `Txid` as a hex-encoded string.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Convert the 32-byte array to a hex string.
        let hex_string = hex::encode(&self.0);
        serializer.serialize_str(&hex_string)
    }
}

impl<'de> Deserialize<'de> for Txid {
    // Deserializes `Txid` from a hex string into a 32-byte array.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // Decode the hex string into bytes.
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            // Validate that the decoded bytes array has the correct length (32 bytes).
            return Err(serde::de::Error::custom(format!(
                "Invalid Txid length: expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut txid_array = [0u8; 32];
        txid_array.copy_from_slice(&bytes);
        Ok(Txid(txid_array))
    }
}

// `OutPoint` identifies a specific transaction output (UTXO) by its transaction ID and output index.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    // Creates a new `OutPoint` from raw transaction ID bytes and an output index.
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        OutPoint {
            txid: Txid(txid),
            vout,
        }
    }

    // Serializes the `OutPoint` into a `Vec<u8>`.
    // Format: txid (32 bytes) + vout (4 bytes, little-endian).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.write_all(&self.txid.0).unwrap(); // Write the 32-byte txid.
        bytes.write_u32::<LittleEndian>(self.vout).unwrap(); // Write the 4-byte vout.
        bytes
    }

    // Deserializes an `OutPoint` from a byte slice.
    // Expects exactly 36 bytes (32 for txid, 4 for vout).
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        if bytes.len() < 36 {
            return Err(BitcoinError::InsufficientBytes);
        }

        let mut cursor = Cursor::new(bytes);
        let mut txid_array = [0u8; 32];
        cursor.read_exact(&mut txid_array)?; // Read 32 bytes for txid.
        let vout = cursor.read_u32::<LittleEndian>()?; // Read 4 bytes for vout.

        Ok((OutPoint::new(txid_array, vout), 36))
    }
}

// `Script` represents a Bitcoin script, which is a sequence of instructions.
// It contains a vector of bytes.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Script {
    pub bytes: Vec<u8>,
}

impl Script {
    // Creates a new `Script` instance from a vector of bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Script { bytes }
    }

    // Serializes the `Script` into a `Vec<u8>`.
    // Format: CompactSize (length of script bytes) + raw script bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let compact_size = CompactSize::new(self.bytes.len() as u64);
        bytes.extend_from_slice(&compact_size.to_bytes()); // Write the CompactSize prefix.
        bytes.extend_from_slice(&self.bytes); // Write the actual script bytes.
        bytes
    }

    // Deserializes a `Script` from a byte slice.
    // First reads the CompactSize length, then reads that many script bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let (compact_size, cs_consumed) = CompactSize::from_bytes(bytes)?;
        let script_len = compact_size.value as usize;

        // Ensure there are enough bytes for the script itself after the CompactSize.
        if bytes.len() < cs_consumed + script_len {
            return Err(BitcoinError::InsufficientBytes);
        }

        let script_bytes_start = cs_consumed;
        let script_bytes_end = cs_consumed + script_len;
        let script_bytes = bytes[script_bytes_start..script_bytes_end].to_vec();

        Ok((Script::new(script_bytes), cs_consumed + script_len))
    }
}

// Allows `&Script` to be used as `&[u8]`, providing direct access to the underlying bytes.
impl Deref for Script {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

// `TransactionInput` represents an input to a Bitcoin transaction.
// It references a previous transaction output, includes a script signature, and a sequence number.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
}

impl TransactionInput {
    // Creates a new `TransactionInput` instance.
    pub fn new(previous_output: OutPoint, script_sig: Script, sequence: u32) -> Self {
        TransactionInput {
            previous_output,
            script_sig,
            sequence,
        }
    }

    // Serializes the `TransactionInput` into a `Vec<u8>`.
    // Format: OutPoint + Script (with CompactSize prefix) + sequence (4 bytes, little-endian).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.previous_output.to_bytes()); // Serialize OutPoint.
        bytes.extend_from_slice(&self.script_sig.to_bytes()); // Serialize Script (includes CompactSize).
        bytes.write_u32::<LittleEndian>(self.sequence).unwrap(); // Write sequence number.
        bytes
    }

    // Deserializes a `TransactionInput` from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let mut consumed_total = 0;

        // Deserialize OutPoint (36 bytes).
        let (previous_output, op_consumed) = OutPoint::from_bytes(bytes)?;
        consumed_total += op_consumed;

        // Deserialize Script (variable length, prefixed by CompactSize).
        let (script_sig, script_consumed) = Script::from_bytes(&bytes[consumed_total..])?;
        consumed_total += script_consumed;

        // Deserialize sequence (4 bytes, little-endian).
        if bytes.len() < consumed_total + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let mut cursor = Cursor::new(&bytes[consumed_total..]);
        let sequence = cursor.read_u32::<LittleEndian>()?;
        consumed_total += 4;

        Ok((
            TransactionInput::new(previous_output, script_sig, sequence),
            consumed_total,
        ))
    }
}

// `BitcoinTransaction` represents a complete Bitcoin transaction.
// It includes a version number, a list of inputs, and a lock time.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub version: u32,
    #[serde(rename = "inputs")] // Rename for JSON serialization if needed
    pub inputs: Vec<TransactionInput>,
    pub lock_time: u32,
}

impl BitcoinTransaction {
    // Creates a new `BitcoinTransaction` instance.
    pub fn new(version: u32, inputs: Vec<TransactionInput>, lock_time: u32) -> Self {
        BitcoinTransaction {
            version,
            inputs,
            lock_time,
        }
    }

    // Serializes the `BitcoinTransaction` into a `Vec<u8>`.
    // Format: version (4 bytes LE) + CompactSize (number of inputs) + each input serialized + lock_time (4 bytes LE).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Version (4 bytes LE).
        bytes.write_u32::<LittleEndian>(self.version).unwrap();

        // CompactSize (number of inputs).
        let input_count_cs = CompactSize::new(self.inputs.len() as u64);
        bytes.extend_from_slice(&input_count_cs.to_bytes());

        // Each input serialized.
        for input in &self.inputs {
            bytes.extend_from_slice(&input.to_bytes());
        }

        // Lock Time (4 bytes LE).
        bytes.write_u32::<LittleEndian>(self.lock_time).unwrap();

        bytes
    }

    // Deserializes a `BitcoinTransaction` from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let mut consumed_total = 0;
        let mut cursor = Cursor::new(bytes);

        // Read version (4 bytes LE).
        if bytes.len() < 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let version = cursor.read_u32::<LittleEndian>()?;
        consumed_total += 4;

        // Read CompactSize for input count.
        let (input_count_cs, cs_consumed) = CompactSize::from_bytes(&bytes[consumed_total..])?;
        let input_count = input_count_cs.value as usize;
        consumed_total += cs_consumed;

        // Parse inputs one by one.
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let (input, input_consumed) = TransactionInput::from_bytes(&bytes[consumed_total..])?;
            inputs.push(input);
            consumed_total += input_consumed;
        }

        // Read final 4 bytes for lock_time.
        if bytes.len() < consumed_total + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let mut lock_time_cursor = Cursor::new(&bytes[consumed_total..]);
        let lock_time = lock_time_cursor.read_u32::<LittleEndian>()?;
        consumed_total += 4;

        Ok((
            BitcoinTransaction::new(version, inputs, lock_time),
            consumed_total,
        ))
    }
}

// Implements `Display` trait for `BitcoinTransaction` to provide a user-friendly string representation.
impl fmt::Display for BitcoinTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Bitcoin Transaction:")?;
        writeln!(f, "  Version: {}", self.version)?;
        writeln!(f, "  Lock Time: {}", self.lock_time)?;
        writeln!(f, "  Inputs ({}):", self.inputs.len())?;
        for (i, input) in self.inputs.iter().enumerate() {
            writeln!(f, "    Input {}:", i)?;
            writeln!(
                f,
                "      Previous Output Txid: {}",
                hex::encode(&input.previous_output.txid.0)
            )?;
            writeln!(
                f,
                "      Previous Output Vout: {}",
                input.previous_output.vout
            )?;
            writeln!(f, "      Script Sig Length: {}", input.script_sig.len())?;
            writeln!(
                f,
                "      Script Sig: {}",
                hex::encode(&input.script_sig.bytes)
            )?;
            writeln!(f, "      Sequence: {}", input.sequence)?;
        }
        Ok(())
    }
}

// Unit tests provided by the user to verify the implementations.
#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_txid(val: u8) -> [u8; 32] {
        let mut txid = [0u8; 32];
        txid[31] = val;
        txid
    }

    #[test]
    fn test_compact_size_serialization() {
        let tests = vec![
            (0u64, vec![0x00]),
            (252u64, vec![0xFC]),
            (253u64, vec![0xFD, 0xFD, 0x00]),
            (65535u64, vec![0xFD, 0xFF, 0xFF]),
            (65536u64, vec![0xFE, 0x00, 0x00, 0x01, 0x00]),
            (4294967295u64, vec![0xFE, 0xFF, 0xFF, 0xFF, 0xFF]),
            (
                4294967296u64,
                vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            ),
        ];

        for (value, bytes) in tests {
            let cs = CompactSize::new(value);
            assert_eq!(cs.to_bytes(), bytes);
            let (decoded, consumed) = CompactSize::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.value, value);
            assert_eq!(consumed, bytes.len());
        }
    }

    #[test]
    fn test_outpoint_roundtrip() {
        let txid = dummy_txid(0xCC);
        let vout = 2;
        let outpoint = OutPoint::new(txid, vout);
        let bytes = outpoint.to_bytes();
        let (parsed, consumed) = OutPoint::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, outpoint);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_script_roundtrip() {
        let script_data = vec![0x76, 0xA9, 0x14, 0x88, 0xAC];
        let script = Script::new(script_data.clone());
        let bytes = script.to_bytes();
        let (parsed, consumed) = Script::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, script);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_tx_input_roundtrip() {
        let outpoint = OutPoint::new(dummy_txid(1), 0);
        let script = Script::new(vec![0x01, 0x02]);
        let input = TransactionInput::new(outpoint.clone(), script.clone(), 0xFFFFFFFF);
        let bytes = input.to_bytes();
        let (parsed, consumed) = TransactionInput::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, input);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_bitcoin_tx_roundtrip() {
        let inputs = vec![TransactionInput::new(
            OutPoint::new(dummy_txid(1), 0),
            Script::new(vec![0x01, 0x02]),
            0xFFFFFFFF,
        )];
        let tx = BitcoinTransaction::new(2, inputs.clone(), 1000);
        let bytes = tx.to_bytes();
        let (parsed, consumed) = BitcoinTransaction::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, tx);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_bitcoin_tx_json_serialization() {
        let input = TransactionInput::new(
            OutPoint::new(dummy_txid(0xAB), 3),
            Script::new(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            0xABCDEF01,
        );
        let tx = BitcoinTransaction::new(1, vec![input], 999);

        let json = serde_json::to_string_pretty(&tx).unwrap();
        let parsed: BitcoinTransaction = serde_json::from_str(&json).unwrap();
        assert_eq!(tx, parsed);

        assert!(json.contains("\"version\": 1"));
        assert!(json.contains("\"lock_time\": 999"));
    }

    #[test]
    fn test_bitcoin_transaction_display() {
        let input = TransactionInput::new(
            OutPoint::new(dummy_txid(0xCD), 7),
            Script::new(vec![0x01, 0x02, 0x03]),
            0xFFFFFFFF,
        );
        let tx = BitcoinTransaction::new(1, vec![input], 0);
        let output = format!("{}", tx);
        assert!(output.contains("Version: 1"));
        assert!(output.contains("Lock Time: 0"));
        assert!(output.contains("Previous Output Vout: 7"));
    }
}
