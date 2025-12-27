//! 共享类型模块
//!
//! 包含枚举类型和辅助结构体，供请求和响应类型共享使用

pub mod enums;
pub mod types;

// 重新导出常用类型
pub use enums::{ContentType, MessageStatus, UserIntent};
pub use types::{
    CodeQuery, ContentSpan, Customization, FollowupPrompt, MostRelevantMissedAlternative,
    ProgrammingLanguage, Reference, SupplementaryWebLink,
};
