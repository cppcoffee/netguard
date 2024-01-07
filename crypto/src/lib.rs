mod builder;
mod keygen;
mod protocol;
mod verifing;

pub use builder::build_packet;
pub use keygen::rsa_keygen;
pub use protocol::NetGuardData;
pub use verifing::verify_knock_packet;

/// Arbitrary maximum for the auth packet
pub const MAX_PACKET_SIZE: usize = 2048;
