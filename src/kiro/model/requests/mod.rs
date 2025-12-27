//! 请求类型模块
//!
//! 包含 Kiro API 请求相关的类型定义

pub mod conversation;
pub mod kiro;
pub mod tool;

// 重新导出主要类型
pub use conversation::{
    AssistantMessage, ConversationState, HistoryAssistantMessage, HistoryUserMessage, KiroImage,
    KiroImageSource, Message, UserInputMessage, UserInputMessageContext, UserMessage,
};
pub use kiro::KiroRequest;
pub use tool::{InputSchema, Tool, ToolResult, ToolSpecification, ToolUseEntry};
