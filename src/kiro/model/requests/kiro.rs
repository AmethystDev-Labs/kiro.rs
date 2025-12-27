//! Kiro 请求类型定义
//!
//! 定义 Kiro API 的主请求结构

use serde::{Deserialize, Serialize};

use super::conversation::ConversationState;

/// Kiro API 请求
///
/// 用于构建发送给 Kiro API 的请求
///
/// # 示例
///
/// ```rust
/// use kiro_rs::kiro::model::requests::{
///     KiroRequest, ConversationState, CurrentMessage, UserInputMessage, Tool
/// };
///
/// // 创建简单请求
/// let state = ConversationState::new("conv-123")
///     .with_agent_task_type("vibe")
///     .with_current_message(CurrentMessage::new(
///         UserInputMessage::new("Hello", "claude-3-5-sonnet")
///     ));
///
/// let request = KiroRequest::new(state);
/// let json = request.to_json().unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KiroRequest {
    /// 对话状态
    pub conversation_state: ConversationState,
}

impl KiroRequest {
    /// 创建新的请求
    pub fn new(conversation_state: ConversationState) -> Self {
        Self { conversation_state }
    }

    /// 序列化为 JSON 字符串
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// 序列化为格式化的 JSON 字符串（用于调试）
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// 获取会话 ID
    pub fn conversation_id(&self) -> &str {
        &self.conversation_state.conversation_id
    }

    /// 获取当前消息内容
    pub fn current_content(&self) -> &str {
        &self
            .conversation_state
            .current_message
            .user_input_message
            .content
    }

    /// 获取模型 ID
    pub fn model_id(&self) -> &str {
        &self
            .conversation_state
            .current_message
            .user_input_message
            .model_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kiro::model::requests::conversation::{CurrentMessage, UserInputMessage};

    #[test]
    fn test_kiro_request_new() {
        let state = ConversationState::new("conv-123").with_current_message(CurrentMessage::new(
            UserInputMessage::new("Hello", "claude-3-5-sonnet"),
        ));

        let request = KiroRequest::new(state);

        assert_eq!(request.conversation_id(), "conv-123");
        assert_eq!(request.current_content(), "Hello");
        assert_eq!(request.model_id(), "claude-3-5-sonnet");
    }

    #[test]
    fn test_kiro_request_serialize() {
        let state = ConversationState::new("conv-123")
            .with_agent_task_type("vibe")
            .with_chat_trigger_type("MANUAL")
            .with_current_message(CurrentMessage::new(
                UserInputMessage::new("Hello", "claude-3-5-sonnet").with_origin("AI_EDITOR"),
            ));

        let request = KiroRequest::new(state);
        let json = request.to_json().unwrap();

        assert!(json.contains("\"conversationState\""));
        assert!(json.contains("\"conversationId\":\"conv-123\""));
        assert!(json.contains("\"agentTaskType\":\"vibe\""));
        assert!(json.contains("\"content\":\"Hello\""));
        assert!(json.contains("\"modelId\":\"claude-3-5-sonnet\""));
    }

    #[test]
    fn test_kiro_request_deserialize() {
        let json = r#"{
            "conversationState": {
                "conversationId": "conv-456",
                "currentMessage": {
                    "userInputMessage": {
                        "content": "Test message",
                        "modelId": "claude-3-5-sonnet",
                        "userInputMessageContext": {}
                    }
                }
            }
        }"#;

        let request: KiroRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.conversation_id(), "conv-456");
        assert_eq!(request.current_content(), "Test message");
    }
}
