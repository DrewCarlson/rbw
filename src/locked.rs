use zeroize::Zeroize as _;

const LEN: usize = 4096;

static MLOCK_WORKS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// RAII guard around `mlock`/`munlock`. `munlock` can spuriously fail with
/// `ENOMEM` on musl under `RLIMIT_MEMLOCK` pressure (common in CI
/// containers); the pages are already released on process exit, so a
/// best-effort unlock is fine — never panic on drop.
struct MlockGuard {
    ptr: *mut core::ffi::c_void,
    len: usize,
}

// The guard only tracks an address + length we own for the lifetime of the
// owning `FixedVec`; it's safe to move across threads.
unsafe impl Send for MlockGuard {}
unsafe impl Sync for MlockGuard {}

impl Drop for MlockGuard {
    fn drop(&mut self) {
        // SAFETY: (ptr, len) came from a successful `mlock` call on a
        // `Box<FixedVec>` that is still live (guard is dropped before the
        // box).
        let _ = unsafe { rustix::mm::munlock(self.ptr, self.len) };
    }
}

fn try_mlock(ptr: *const u8, len: usize) -> rustix::io::Result<MlockGuard> {
    // rustix takes *mut c_void; mlock doesn't mutate, but the POSIX
    // signature is *mut.
    let p = ptr.cast::<core::ffi::c_void>().cast_mut();
    // SAFETY: `ptr` points to a live allocation of at least `len` bytes
    // owned by the caller.
    unsafe { rustix::mm::mlock(p, len) }?;
    Ok(MlockGuard { ptr: p, len })
}

pub struct FixedVec<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> FixedVec<N> {
    fn new() -> Self {
        Self {
            data: [0u8; N],
            len: 0,
        }
    }

    const fn capacity() -> usize {
        N
    }

    fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
        }
    }

    fn extend(&mut self, it: impl Iterator<Item = u8>) {
        for b in it {
            assert!(self.len < N, "FixedVec capacity exceeded");
            self.data[self.len] = b;
            self.len += 1;
        }
    }
}

impl<const N: usize> Drop for FixedVec<N> {
    fn drop(&mut self) {
        self.data[..self.len].zeroize();
    }
}

pub struct Vec {
    data: Box<FixedVec<LEN>>,
    _lock: Option<MlockGuard>,
}

impl Default for Vec {
    fn default() -> Self {
        let data = Box::new(FixedVec::<LEN>::new());
        let lock = match MLOCK_WORKS.get() {
            Some(true) => try_mlock(data.as_ptr(), FixedVec::<LEN>::capacity())
                .ok(),
            Some(false) => None,
            None => {
                match try_mlock(data.as_ptr(), FixedVec::<LEN>::capacity()) {
                    Ok(lock) => {
                        let _ = MLOCK_WORKS.set(true);
                        Some(lock)
                    }
                    Err(e) => {
                        if MLOCK_WORKS.set(false).is_ok() {
                            eprintln!("failed to lock memory region: {e}");
                        }
                        None
                    }
                }
            }
        };
        Self { data, _lock: lock }
    }
}

impl Vec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    pub fn zero(&mut self) {
        self.truncate(0);
        self.data.extend(std::iter::repeat_n(0, LEN));
    }

    pub fn extend(&mut self, it: impl Iterator<Item = u8>) {
        self.data.extend(it);
    }

    pub fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
    }
}

impl Drop for Vec {
    fn drop(&mut self) {
        self.zero();
        self.data.as_mut_slice().zeroize();
    }
}

impl Clone for Vec {
    fn clone(&self) -> Self {
        let mut new_vec = Self::new();
        new_vec.extend(self.data().iter().copied());
        new_vec
    }
}

#[derive(Clone)]
pub struct Password {
    password: Vec,
}

impl Password {
    pub fn new(password: Vec) -> Self {
        Self { password }
    }

    pub fn password(&self) -> &[u8] {
        self.password.data()
    }
}

#[derive(Clone)]
pub struct Keys {
    keys: Vec,
}

impl Keys {
    pub fn new(keys: Vec) -> Self {
        Self { keys }
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.keys.data()[0..32]
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.keys.data()[32..64]
    }

    /// Full 64-byte `enc_key` || `mac_key` buffer. Used by Touch ID
    /// enroll to wrap the vault keys into a `CipherString`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.keys.data()[0..64]
    }
}

#[derive(Clone)]
pub struct PasswordHash {
    hash: Vec,
}

impl PasswordHash {
    pub fn new(hash: Vec) -> Self {
        Self { hash }
    }

    pub fn hash(&self) -> &[u8] {
        self.hash.data()
    }
}

#[derive(Clone)]
pub struct PrivateKey {
    private_key: Vec,
}

impl PrivateKey {
    pub fn new(private_key: Vec) -> Self {
        Self { private_key }
    }

    pub fn private_key(&self) -> &[u8] {
        self.private_key.data()
    }
}

#[derive(Clone)]
pub struct ApiKey {
    client_id: Password,
    client_secret: Password,
}

impl ApiKey {
    pub fn new(client_id: Password, client_secret: Password) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }

    pub fn client_id(&self) -> &[u8] {
        self.client_id.password()
    }

    pub fn client_secret(&self) -> &[u8] {
        self.client_secret.password()
    }
}

#[cfg(test)]
mod tests {
    use super::FixedVec;

    #[test]
    fn push_len_and_slice() {
        let mut v = FixedVec::<8>::new();
        v.extend([1u8, 2, 3, 4].into_iter());
        assert_eq!(v.as_slice().len(), 4);
        assert_eq!(v.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn truncate_and_clear() {
        let mut v = FixedVec::<8>::new();
        v.extend([1u8, 2, 3, 4].into_iter());
        v.truncate(0);
        assert!(v.as_slice().is_empty());
        assert_eq!(v.data[..4], [1, 2, 3, 4]);
    }

    #[test]
    #[should_panic(expected = "FixedVec capacity exceeded")]
    fn push_past_capacity_panics() {
        let mut v = FixedVec::<2>::new();
        v.extend([1u8, 2, 3].into_iter());
    }
}
