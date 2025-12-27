//! 枚举类型定义
//!
//! 定义 Kiro API 使用的枚举类型

use serde::{Deserialize, Serialize};
use std::fmt;

/// 消息状态
///
/// 表示助手响应消息的当前状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageStatus {
    /// 消息已完成
    Completed,
    /// 消息处理中
    InProgress,
    /// 消息出错
    Error,
}

impl MessageStatus {
    /// 转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "COMPLETED",
            Self::InProgress => "IN_PROGRESS",
            Self::Error => "ERROR",
        }
    }

    /// 从字符串解析
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "COMPLETED" => Some(Self::Completed),
            "IN_PROGRESS" => Some(Self::InProgress),
            "ERROR" => Some(Self::Error),
            _ => None,
        }
    }

    /// 判断是否已完成
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }

    /// 判断是否出错
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error)
    }
}

impl Default for MessageStatus {
    fn default() -> Self {
        Self::InProgress
    }
}

impl fmt::Display for MessageStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// 用户意图
///
/// 表示用户请求的意图类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserIntent {
    /// 解释代码选择
    ExplainCodeSelection,
    /// 建议替代实现
    SuggestAlternateImplementation,
    /// 应用常见最佳实践
    ApplyCommonBestPractices,
    /// 改进代码
    ImproveCode,
    /// 展示示例
    ShowExamples,
    /// 引用来源
    CiteSources,
    /// 逐行解释
    ExplainLineByLine,
}

impl UserIntent {
    /// 转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExplainCodeSelection => "EXPLAIN_CODE_SELECTION",
            Self::SuggestAlternateImplementation => "SUGGEST_ALTERNATE_IMPLEMENTATION",
            Self::ApplyCommonBestPractices => "APPLY_COMMON_BEST_PRACTICES",
            Self::ImproveCode => "IMPROVE_CODE",
            Self::ShowExamples => "SHOW_EXAMPLES",
            Self::CiteSources => "CITE_SOURCES",
            Self::ExplainLineByLine => "EXPLAIN_LINE_BY_LINE",
        }
    }

    /// 从字符串解析
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "EXPLAIN_CODE_SELECTION" => Some(Self::ExplainCodeSelection),
            "SUGGEST_ALTERNATE_IMPLEMENTATION" => Some(Self::SuggestAlternateImplementation),
            "APPLY_COMMON_BEST_PRACTICES" => Some(Self::ApplyCommonBestPractices),
            "IMPROVE_CODE" => Some(Self::ImproveCode),
            "SHOW_EXAMPLES" => Some(Self::ShowExamples),
            "CITE_SOURCES" => Some(Self::CiteSources),
            "EXPLAIN_LINE_BY_LINE" => Some(Self::ExplainLineByLine),
            _ => None,
        }
    }
}

impl fmt::Display for UserIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// 内容类型
///
/// 表示响应内容的 MIME 类型
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContentType {
    /// Markdown 格式
    #[serde(rename = "text/markdown")]
    Markdown,
    /// 纯文本格式
    #[serde(rename = "text/plain")]
    Plain,
    /// JSON 格式
    #[serde(rename = "application/json")]
    Json,
}

impl ContentType {
    /// 转换为 MIME 类型字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Markdown => "text/markdown",
            Self::Plain => "text/plain",
            Self::Json => "application/json",
        }
    }

    /// 从 MIME 类型字符串解析
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "text/markdown" => Some(Self::Markdown),
            "text/plain" => Some(Self::Plain),
            "application/json" => Some(Self::Json),
            _ => None,
        }
    }

    /// 判断是否为 Markdown
    pub fn is_markdown(&self) -> bool {
        matches!(self, Self::Markdown)
    }
}

impl Default for ContentType {
    fn default() -> Self {
        Self::Markdown
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_status_serialize() {
        assert_eq!(
            serde_json::to_string(&MessageStatus::Completed).unwrap(),
            "\"COMPLETED\""
        );
        assert_eq!(
            serde_json::to_string(&MessageStatus::InProgress).unwrap(),
            "\"IN_PROGRESS\""
        );
        assert_eq!(
            serde_json::to_string(&MessageStatus::Error).unwrap(),
            "\"ERROR\""
        );
    }

    #[test]
    fn test_message_status_deserialize() {
        assert_eq!(
            serde_json::from_str::<MessageStatus>("\"COMPLETED\"").unwrap(),
            MessageStatus::Completed
        );
        assert_eq!(
            serde_json::from_str::<MessageStatus>("\"IN_PROGRESS\"").unwrap(),
            MessageStatus::InProgress
        );
    }

    #[test]
    fn test_user_intent_serialize() {
        assert_eq!(
            serde_json::to_string(&UserIntent::ExplainCodeSelection).unwrap(),
            "\"EXPLAIN_CODE_SELECTION\""
        );
        assert_eq!(
            serde_json::to_string(&UserIntent::ImproveCode).unwrap(),
            "\"IMPROVE_CODE\""
        );
    }

    #[test]
    fn test_content_type_serialize() {
        assert_eq!(
            serde_json::to_string(&ContentType::Markdown).unwrap(),
            "\"text/markdown\""
        );
        assert_eq!(
            serde_json::to_string(&ContentType::Plain).unwrap(),
            "\"text/plain\""
        );
        assert_eq!(
            serde_json::to_string(&ContentType::Json).unwrap(),
            "\"application/json\""
        );
    }

    #[test]
    fn test_content_type_deserialize() {
        assert_eq!(
            serde_json::from_str::<ContentType>("\"text/markdown\"").unwrap(),
            ContentType::Markdown
        );
    }

    #[test]
    fn test_message_status_display() {
        assert_eq!(format!("{}", MessageStatus::Completed), "COMPLETED");
        assert_eq!(format!("{}", MessageStatus::InProgress), "IN_PROGRESS");
    }

    #[test]
    fn test_content_type_display() {
        assert_eq!(format!("{}", ContentType::Markdown), "text/markdown");
    }
}
