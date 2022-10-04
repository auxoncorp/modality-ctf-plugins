use derive_more::{Display, From, Into};
use serde::Deserialize;
use std::convert::TryFrom;
use std::num::ParseIntError;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::Arc;

#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct Interruptor(Arc<AtomicBool>);

impl Interruptor {
    pub fn new() -> Self {
        Interruptor(Arc::new(AtomicBool::new(false)))
    }

    pub fn set(&self) {
        self.0.store(true, SeqCst);
    }

    pub fn is_set(&self) -> bool {
        self.0.load(SeqCst)
    }
}

impl Default for Interruptor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, From, Into, Display,
)]
#[repr(transparent)]
pub struct RetryDurationUs(pub u64);

impl Default for RetryDurationUs {
    fn default() -> Self {
        // 100ms
        RetryDurationUs(100000)
    }
}

impl FromStr for RetryDurationUs {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(RetryDurationUs(s.trim().parse::<u64>()?))
    }
}

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, From, Into, Display,
)]
#[serde(try_from = "String", into = "String")]
pub struct LoggingLevel(pub babeltrace2_sys::LoggingLevel);

impl Default for LoggingLevel {
    fn default() -> Self {
        LoggingLevel(babeltrace2_sys::LoggingLevel::None)
    }
}

impl TryFrom<String> for LoggingLevel {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(LoggingLevel(babeltrace2_sys::LoggingLevel::from_str(&s)?))
    }
}

impl FromStr for LoggingLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(LoggingLevel(babeltrace2_sys::LoggingLevel::from_str(s)?))
    }
}

#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, From, Into, Display,
)]
#[serde(try_from = "String", into = "String")]
pub struct SessionNotFoundAction(pub babeltrace2_sys::SessionNotFoundAction);

impl Default for SessionNotFoundAction {
    fn default() -> Self {
        SessionNotFoundAction(babeltrace2_sys::SessionNotFoundAction::Continue)
    }
}

impl TryFrom<String> for SessionNotFoundAction {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(SessionNotFoundAction(
            babeltrace2_sys::SessionNotFoundAction::from_str(&s)?,
        ))
    }
}

impl FromStr for SessionNotFoundAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SessionNotFoundAction(
            babeltrace2_sys::SessionNotFoundAction::from_str(s)?,
        ))
    }
}
