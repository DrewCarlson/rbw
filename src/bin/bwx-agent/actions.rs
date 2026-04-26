mod auth;
mod crypto;
mod ssh;
mod sync;
mod touchid;
mod util;

pub use auth::{check_lock, lock, login, register, unlock};
pub use crypto::{clipboard_store, decrypt, decrypt_batch, encrypt, version};
pub use ssh::{
    decrypt_located_ssh_private_key, get_ssh_public_keys,
    locate_ssh_private_key,
};
pub use sync::sync;
pub use touchid::{touchid_disable, touchid_enroll, touchid_status};
