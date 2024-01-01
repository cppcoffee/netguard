/// NetGuardData protocol data
#[derive(Debug)]
pub struct NetGuardData {
    pub timestamp: u64,
    pub unlock_port: u16,
}

impl NetGuardData {
    pub fn new(timestamp: u64, unlock_port: u16) -> Self {
        Self {
            timestamp,
            unlock_port,
        }
    }

    pub fn to_network_vec(&self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend(self.timestamp.to_be_bytes());
        res.extend(self.unlock_port.to_be_bytes());
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netguard_data() {
        let data = NetGuardData::new(123, 456);
        assert_eq!(data.timestamp, 123);
        assert_eq!(data.unlock_port, 456);

        let network_data = data.to_network_vec();
        assert_eq!(network_data.len(), 10);

        assert_eq!(network_data[0..8], 123u64.to_be_bytes());
        assert_eq!(network_data[8..], 456u16.to_be_bytes());
    }
}
