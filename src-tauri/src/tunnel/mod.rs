//! 隧道：argv 构建、事件解析、子进程监管

pub mod argv;
pub mod events;
pub mod occonfig;
pub mod signal;
pub mod supervisor;

pub use argv::{ArgPlan, Secrets, StdinSecret};
pub use events::{parse_line, Event, Kind, Level, State, TerminalCause, Tracker};
