//! 助手响应事件
//!
//! 处理 assistantResponseEvent 类型的事件

use serde::{Deserialize, Serialize};

use crate::kiro::model::common::{
    CodeQuery, ContentType, Customization, FollowupPrompt, MessageStatus, ProgrammingLanguage,
    Reference, SupplementaryWebLink, UserIntent,
};
use crate::kiro::parser::error::ParseResult;
use crate::kiro::parser::frame::Frame;

use super::base::{EventPayload, EventType};

/// 助手响应事件
///
/// 包含 AI 助手的流式响应内容和元数据
///
/// # 向后兼容性
///
/// 此结构体扩展了原有的简化版本，所有新增字段都是可选的，
/// 确保现有代码继续正常工作。对于流式响应，通常只有 `content` 字段有值。
///
/// # 示例
///
/// ```rust
/// use kiro_rs::kiro::model::events::AssistantResponseEvent;
///
/// // 简单的流式响应（只有 content）
/// let json = r#"{"content":"Hello, world!"}"#;
/// let event: AssistantResponseEvent = serde_json::from_str(json).unwrap();
/// assert_eq!(event.content(), "Hello, world!");
///
/// // 完整响应（包含所有元数据）
/// let full_json = r#"{
///     "content": "Here is the answer",
///     "conversationId": "conv-123",
///     "messageId": "msg-456",
///     "messageStatus": "COMPLETED",
///     "contentType": "text/markdown"
/// }"#;
/// let full_event: AssistantResponseEvent = serde_json::from_str(full_json).unwrap();
/// assert!(full_event.is_completed());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantResponseEvent {
    // ========== 核心字段 ==========
    /// 响应内容片段
    #[serde(default)]
    pub content: String,

    /// 会话 ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,

    /// 消息 ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,

    /// 内容类型（如 text/markdown, text/plain）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<ContentType>,

    /// 消息状态（COMPLETED, IN_PROGRESS, ERROR）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_status: Option<MessageStatus>,

    // ========== 引用和链接字段 ==========
    /// 补充网页链接
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supplementary_web_links: Vec<SupplementaryWebLink>,

    /// 代码引用
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<Reference>,

    /// 代码引用（另一种格式）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_reference: Vec<Reference>,

    // ========== 交互字段 ==========
    /// 后续提示
    #[serde(skip_serializing_if = "Option::is_none")]
    pub followup_prompt: Option<FollowupPrompt>,

    // ========== 上下文字段 ==========
    /// 编程语言
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programming_language: Option<ProgrammingLanguage>,

    /// 定制化配置列表
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub customizations: Vec<Customization>,

    /// 用户意图
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_intent: Option<UserIntent>,

    /// 代码查询
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_query: Option<CodeQuery>,
}

impl EventPayload for AssistantResponseEvent {
    fn from_frame(frame: &Frame) -> ParseResult<Self> {
        frame.payload_as_json()
    }

    fn event_type() -> EventType {
        EventType::AssistantResponse
    }
}

impl AssistantResponseEvent {
    // ========== 内容相关方法（保持向后兼容） ==========

    /// 获取内容
    pub fn content(&self) -> &str {
        &self.content
    }

    /// 判断内容是否为空
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// 获取内容长度
    pub fn len(&self) -> usize {
        self.content.len()
    }

    // ========== 状态相关方法 ==========

    /// 判断消息是否已完成
    pub fn is_completed(&self) -> bool {
        matches!(self.message_status, Some(MessageStatus::Completed))
    }

    /// 判断消息是否处理中
    pub fn is_in_progress(&self) -> bool {
        matches!(self.message_status, Some(MessageStatus::InProgress))
    }

    /// 判断消息是否出错
    pub fn is_error(&self) -> bool {
        matches!(self.message_status, Some(MessageStatus::Error))
    }

    // ========== 引用相关方法 ==========

    /// 判断是否有引用
    pub fn has_references(&self) -> bool {
        !self.references.is_empty() || !self.code_reference.is_empty()
    }

    /// 判断是否有网页链接
    pub fn has_web_links(&self) -> bool {
        !self.supplementary_web_links.is_empty()
    }

    /// 获取所有引用（合并 references 和 code_reference）
    pub fn all_references(&self) -> impl Iterator<Item = &Reference> {
        self.references.iter().chain(self.code_reference.iter())
    }

    // ========== 会话相关方法 ==========

    /// 获取会话 ID
    pub fn conversation_id(&self) -> Option<&str> {
        self.conversation_id.as_deref()
    }

    /// 获取消息 ID
    pub fn message_id(&self) -> Option<&str> {
        self.message_id.as_deref()
    }

    // ========== 内容类型方法 ==========

    /// 判断内容是否为 Markdown 格式
    pub fn is_markdown(&self) -> bool {
        matches!(self.content_type, Some(ContentType::Markdown))
    }

    /// 判断内容是否为纯文本格式
    pub fn is_plain_text(&self) -> bool {
        matches!(self.content_type, Some(ContentType::Plain))
    }

    /// 判断内容是否为 JSON 格式
    pub fn is_json(&self) -> bool {
        matches!(self.content_type, Some(ContentType::Json))
    }
}

impl Default for AssistantResponseEvent {
    fn default() -> Self {
        Self {
            content: String::new(),
            conversation_id: None,
            message_id: None,
            content_type: None,
            message_status: None,
            supplementary_web_links: Vec::new(),
            references: Vec::new(),
            code_reference: Vec::new(),
            followup_prompt: None,
            programming_language: None,
            customizations: Vec::new(),
            user_intent: None,
            code_query: None,
        }
    }
}

impl std::fmt::Display for AssistantResponseEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_simple() {
        // 测试简单的流式响应（只有 content）
        let json = r#"{"content":"Hello, world!"}"#;
        let event: AssistantResponseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.content(), "Hello, world!");
        assert!(event.conversation_id.is_none());
        assert!(event.message_id.is_none());
    }

    #[test]
    fn test_deserialize_empty() {
        // 测试空 JSON（向后兼容）
        let json = r#"{}"#;
        let event: AssistantResponseEvent = serde_json::from_str(json).unwrap();
        assert!(event.is_empty());
    }

    #[test]
    fn test_deserialize_full() {
        // 测试完整响应
        let json = r#"{
            "content": "Here is the answer",
            "conversationId": "conv-123",
            "messageId": "msg-456",
            "messageStatus": "COMPLETED",
            "contentType": "text/markdown"
        }"#;
        let event: AssistantResponseEvent = serde_json::from_str(json).unwrap();

        assert_eq!(event.content(), "Here is the answer");
        assert_eq!(event.conversation_id(), Some("conv-123"));
        assert_eq!(event.message_id(), Some("msg-456"));
        assert!(event.is_completed());
        assert!(event.is_markdown());
    }

    #[test]
    fn test_deserialize_with_references() {
        let json = r#"{
            "content": "Code example",
            "references": [
                {"licenseName": "MIT", "repository": "example/repo"}
            ],
            "supplementaryWebLinks": [
                {"url": "https://example.com", "title": "Example", "score": 0.95}
            ]
        }"#;
        let event: AssistantResponseEvent = serde_json::from_str(json).unwrap();

        assert!(event.has_references());
        assert!(event.has_web_links());
        assert_eq!(event.references.len(), 1);
        assert_eq!(event.supplementary_web_links.len(), 1);
    }

    #[test]
    fn test_deserialize_with_followup() {
        let json = r#"{
            "content": "Done",
            "followupPrompt": {
                "content": "Would you like me to explain further?",
                "userIntent": "EXPLAIN_CODE_SELECTION"
            }
        }"#;
        let event: AssistantResponseEvent = serde_json::from_str(json).unwrap();

        assert!(event.followup_prompt.is_some());
        let prompt = event.followup_prompt.unwrap();
        assert_eq!(prompt.content, "Would you like me to explain further?");
        assert_eq!(prompt.user_intent, Some(UserIntent::ExplainCodeSelection));
    }

    #[test]
    fn test_serialize_minimal() {
        // 测试序列化时跳过空字段
        let event = AssistantResponseEvent {
            content: "Test".to_string(),
            ..Default::default()
        };

        let json = serde_json::to_string(&event).unwrap();
        // 应该只包含 content 字段
        assert!(json.contains("\"content\":\"Test\""));
        // 不应该包含空的可选字段
        assert!(!json.contains("conversationId"));
        assert!(!json.contains("supplementaryWebLinks"));
    }

    #[test]
    fn test_display() {
        let event = AssistantResponseEvent {
            content: "test".to_string(),
            ..Default::default()
        };
        assert_eq!(format!("{}", event), "test");
    }

    #[test]
    fn test_message_status() {
        let completed = AssistantResponseEvent {
            message_status: Some(MessageStatus::Completed),
            ..Default::default()
        };
        assert!(completed.is_completed());
        assert!(!completed.is_in_progress());
        assert!(!completed.is_error());

        let in_progress = AssistantResponseEvent {
            message_status: Some(MessageStatus::InProgress),
            ..Default::default()
        };
        assert!(in_progress.is_in_progress());

        let error = AssistantResponseEvent {
            message_status: Some(MessageStatus::Error),
            ..Default::default()
        };
        assert!(error.is_error());
    }

    #[test]
    fn test_all_references() {
        let event = AssistantResponseEvent {
            references: vec![Reference::new().with_license_name("MIT")],
            code_reference: vec![Reference::new().with_license_name("Apache-2.0")],
            ..Default::default()
        };

        let all_refs: Vec<_> = event.all_references().collect();
        assert_eq!(all_refs.len(), 2);
    }

    #[test]
    fn test_content_type() {
        let markdown = AssistantResponseEvent {
            content_type: Some(ContentType::Markdown),
            ..Default::default()
        };
        assert!(markdown.is_markdown());
        assert!(!markdown.is_plain_text());
        assert!(!markdown.is_json());

        let json_type = AssistantResponseEvent {
            content_type: Some(ContentType::Json),
            ..Default::default()
        };
        assert!(json_type.is_json());
    }
}
