use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Debug, Clone)]
pub struct RainbowChain {
    pub start: String,
    pub end: String,
}

#[derive(Debug, Clone)]
pub struct RainbowTable {
    pub name: String,
    pub hash_type: String,
    pub chain_length: usize,
    pub chains: Vec<RainbowChain>,
    pub table: HashMap<String, String>,
}

impl RainbowTable {
    pub fn new(name: &str, hash_type: &str, chain_length: usize) -> Self {
        RainbowTable {
            name: name.to_string(),
            hash_type: hash_type.to_string(),
            chain_length,
            chains: Vec::new(),
            table: HashMap::new(),
        }
    }

    pub fn load_csv(path: &str, hash_type: &str) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("Cannot open table: {}", e))?;
        let reader = BufReader::new(file);
        let mut chains = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Read error: {}", e))?;
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 2 {
                chains.push(RainbowChain {
                    start: parts[0].trim().to_string(),
                    end: parts[1].trim().to_string(),
                });
            }
        }

        let name = std::path::Path::new(path)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let mut table = RainbowTable {
            name,
            hash_type: hash_type.to_string(),
            chain_length: 1000,
            chains,
            table: HashMap::new(),
        };
        table.build_index();
        Ok(table)
    }

    pub fn build_index(&mut self) {
        for chain in &self.chains {
            self.table.insert(chain.end.clone(), chain.start.clone());
        }
    }

    pub fn build_from_wordlist(path: &str, reduction_func: fn(&str) -> String) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("Cannot open wordlist: {}", e))?;
        let reader = BufReader::new(file);
        let mut chains = Vec::new();
        let mut table = HashMap::new();

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Read error: {}", e))?;
            let password = line.trim().to_string();
            if password.is_empty() {
                continue;
            }

            let mut current = password.clone();
            for _ in 0..1000 {
                let hash = reduction_func(&current);
                current = hash;
            }
            let end = current;

            chains.push(RainbowChain {
                start: password.clone(),
                end: end.clone(),
            });
            table.insert(end, password);
        }

        Ok(RainbowTable {
            name: "builtin".to_string(),
            hash_type: "custom".to_string(),
            chain_length: 1000,
            chains,
            table,
        })
    }

    pub fn lookup(&self, hash: &str, reduction_func: fn(&str) -> String) -> Option<String> {
        let mut current = hash.to_string();

        for _ in 0..self.chain_length {
            if let Some(password) = self.table.get(&current) {
                let candidate = self.verify_chain(password, hash, reduction_func);
                if let Some(found) = candidate {
                    return Some(found);
                }
            }
            current = reduction_func(&current);
        }
        None
    }

    fn verify_chain(&self, start: &str, target_hash: &str, reduction_func: fn(&str) -> String) -> Option<String> {
        let mut current = start.to_string();
        for _ in 0..self.chain_length {
            let hash = reduction_func(&current);
            if hash == target_hash {
                return Some(current);
            }
            current = hash;
        }
        None
    }

    pub fn lookup_plaintext(&self, hash: &str) -> Option<&String> {
        self.table.get(hash)
    }

    pub fn import_rainbowcrack(path: &str, hash_type: &str) -> Result<Self, String> {
        Self::load_csv(path, hash_type)
    }

    pub fn chain_count(&self) -> usize {
        self.chains.len()
    }

    pub fn coverage_estimate(&self) -> usize {
        self.chains.len() * self.chain_length
    }
}

fn hex_reduction(input: &str) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(input.as_bytes());
    let hex = format!("{:x}", hash);
    hex[..16].to_string()
}

fn md5_reduction(input: &str) -> String {
    use md5::Digest;
    let digest = md5::Md5::digest(input.as_bytes());
    format!("{:x}", digest)
}

pub fn lookup_md5(table: &RainbowTable, hash: &str) -> Option<String> {
    table.lookup(hash, md5_reduction)
}

pub fn lookup_sha256(table: &RainbowTable, hash: &str) -> Option<String> {
    table.lookup(hash, hex_reduction)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rainbow_table_new() {
        let table = RainbowTable::new("test", "MD5", 1000);
        assert_eq!(table.name, "test");
        assert_eq!(table.hash_type, "MD5");
        assert_eq!(table.chain_length, 1000);
    }

    #[test]
    fn test_hex_reduction_length() {
        let result = hex_reduction("test");
        assert_eq!(result.len(), 16);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_md5_reduction() {
        let result = md5_reduction("hello");
        assert_eq!(result.len(), 32);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_build_from_wordlist() {
        let path = "/tmp/test_rainbow_wordlist.txt";
        let mut f = File::create(path).unwrap();
        use std::io::Write;
        writeln!(f, "password").ok();
        writeln!(f, "hello").ok();
        writeln!(f, "admin").ok();

        let table = RainbowTable::build_from_wordlist(path, hex_reduction).unwrap();
        assert_eq!(table.chain_count(), 3);
        assert!(table.coverage_estimate() >= 3000);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_import_csv_not_found() {
        let result = RainbowTable::load_csv("/tmp/nonexistent_rainbow.csv", "MD5");
        assert!(result.is_err());
    }

    #[test]
    fn test_lookup_plaintext() {
        let mut table = RainbowTable::new("test", "MD5", 1000);
        table.table.insert("abc123hash".to_string(), "mypassword".to_string());
        assert_eq!(table.lookup_plaintext("abc123hash"), Some(&"mypassword".to_string()));
    }

    #[test]
    fn test_lookup_empty_table() {
        let table = RainbowTable::new("empty", "MD5", 1000);
        let result = table.lookup("somehash", hex_reduction);
        assert!(result.is_none());
    }
}
