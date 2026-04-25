// Error type used by the bwx-agent binary. It provides both a simple
// message variant and a "with context" variant that wraps another error,
// roughly mimicking the anyhow API used previously.

use std::fmt;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub enum Error {
    Msg(String),
    WithContext { context: String, source: BoxError },
    Boxed(BoxError),
}

impl Error {
    pub fn msg<S: Into<String>>(s: S) -> Self {
        Self::Msg(s.into())
    }

    pub fn with_context<E: Into<BoxError>, S: Into<String>>(
        e: E,
        context: S,
    ) -> Self {
        Self::WithContext {
            context: context.into(),
            source: e.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Msg(s) => f.write_str(s),
            Self::WithContext { context, source } => {
                if f.alternate() {
                    write!(f, "{context}: {source:#}")
                } else {
                    write!(f, "{context}: {source}")
                }
            }
            Self::Boxed(e) => {
                if f.alternate() {
                    write!(f, "{e:#}")
                } else {
                    write!(f, "{e}")
                }
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WithContext { source, .. } | Self::Boxed(source) => {
                Some(&**source)
            }
            Self::Msg(_) => None,
        }
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Self::Msg(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Self::Msg(s.to_string())
    }
}

macro_rules! impl_from {
    ($($ty:ty),* $(,)?) => {
        $(
            impl From<$ty> for Error {
                fn from(e: $ty) -> Self {
                    Self::Boxed(Box::new(e))
                }
            }
        )*
    };
}

impl_from!(
    bwx::error::Error,
    std::io::Error,
    serde_json::Error,
    rustix::io::Errno,
    reqwest::Error,
    tokio::task::JoinError,
);

pub type Result<T> = std::result::Result<T, Error>;

#[allow(dead_code)]
pub trait ContextExt<T, E> {
    fn context<S: Into<String>>(self, ctx: S) -> Result<T>;
    fn with_context<S: Into<String>, F: FnOnce() -> S>(
        self,
        f: F,
    ) -> Result<T>;
}

impl<T, E: Into<BoxError>> ContextExt<T, E> for std::result::Result<T, E> {
    fn context<S: Into<String>>(self, ctx: S) -> Result<T> {
        self.map_err(|e| Error::with_context(e, ctx))
    }

    fn with_context<S: Into<String>, F: FnOnce() -> S>(
        self,
        f: F,
    ) -> Result<T> {
        self.map_err(|e| Error::with_context(e, f()))
    }
}

impl<T> ContextExt<T, Error> for Option<T> {
    fn context<S: Into<String>>(self, ctx: S) -> Result<T> {
        self.ok_or_else(|| Error::msg(ctx))
    }

    fn with_context<S: Into<String>, F: FnOnce() -> S>(
        self,
        f: F,
    ) -> Result<T> {
        self.ok_or_else(|| Error::msg(f()))
    }
}
