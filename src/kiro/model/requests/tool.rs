//! 工具类型定义
//!
//! 定义 Kiro API 中工具相关的类型

use serde::{Deserialize, Serialize};

/// 工具定义
///
/// 用于在请求中定义可用的工具
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    /// 工具规范
    pub tool_specification: ToolSpecification,
}

impl Tool {
    /// 创建新的工具定义
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> ToolBuilder {
        ToolBuilder::new(name, description)
    }

    /// 获取工具名称
    pub fn name(&self) -> &str {
        &self.tool_specification.name
    }

    /// 获取工具描述
    pub fn description(&self) -> &str {
        &self.tool_specification.description
    }
}

/// 工具规范
///
/// 定义工具的名称、描述和输入模式
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolSpecification {
    /// 工具名称
    pub name: String,
    /// 工具描述
    pub description: String,
    /// 输入模式（JSON Schema）
    pub input_schema: InputSchema,
}

impl ToolSpecification {
    /// 创建新的工具规范
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema: InputSchema::default(),
        }
    }

    /// 设置输入模式
    pub fn with_input_schema(mut self, schema: serde_json::Value) -> Self {
        self.input_schema = InputSchema { json: schema };
        self
    }
}

/// 输入模式
///
/// 包装 JSON Schema 定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSchema {
    /// JSON Schema 定义
    pub json: serde_json::Value,
}

impl Default for InputSchema {
    fn default() -> Self {
        Self {
            json: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        }
    }
}

impl InputSchema {
    /// 从 JSON 值创建
    pub fn from_json(json: serde_json::Value) -> Self {
        Self { json }
    }

    /// 创建空的输入模式
    pub fn empty() -> Self {
        Self::default()
    }
}

/// 工具执行结果
///
/// 用于返回工具执行的结果
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResult {
    /// 工具使用 ID（与请求中的 tool_use_id 对应）
    pub tool_use_id: String,
    /// 结果内容（数组格式）
    pub content: Vec<serde_json::Map<String, serde_json::Value>>,
    /// 执行状态（"success" 或 "error"）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// 是否为错误
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_error: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl ToolResult {
    /// 创建成功的工具结果
    pub fn success(tool_use_id: impl Into<String>, content: impl Into<String>) -> Self {
        let mut map = serde_json::Map::new();
        map.insert("text".to_string(), serde_json::Value::String(content.into()));

        Self {
            tool_use_id: tool_use_id.into(),
            content: vec![map],
            status: Some("success".to_string()),
            is_error: false,
        }
    }

    /// 创建错误的工具结果
    pub fn error(tool_use_id: impl Into<String>, error_message: impl Into<String>) -> Self {
        let mut map = serde_json::Map::new();
        map.insert(
            "text".to_string(),
            serde_json::Value::String(error_message.into()),
        );

        Self {
            tool_use_id: tool_use_id.into(),
            content: vec![map],
            status: Some("error".to_string()),
            is_error: true,
        }
    }

    /// 从 JSON 值创建工具结果
    pub fn from_json(tool_use_id: impl Into<String>, json: serde_json::Value) -> Self {
        let content = if let Some(obj) = json.as_object() {
            vec![obj.clone()]
        } else {
            let mut map = serde_json::Map::new();
            map.insert("value".to_string(), json);
            vec![map]
        };

        Self {
            tool_use_id: tool_use_id.into(),
            content,
            status: Some("success".to_string()),
            is_error: false,
        }
    }

    /// 判断是否成功
    pub fn is_success(&self) -> bool {
        !self.is_error && self.status.as_deref() != Some("error")
    }
}

/// 工具使用条目
///
/// 用于历史消息中记录工具调用
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolUseEntry {
    /// 工具使用 ID
    pub tool_use_id: String,
    /// 工具名称
    pub name: String,
    /// 工具输入参数
    pub input: serde_json::Value,
}

impl ToolUseEntry {
    /// 创建新的工具使用条目
    pub fn new(tool_use_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            tool_use_id: tool_use_id.into(),
            name: name.into(),
            input: serde_json::json!({}),
        }
    }

    /// 设置输入参数
    pub fn with_input(mut self, input: serde_json::Value) -> Self {
        self.input = input;
        self
    }
}

/// 工具构建器
///
/// 用于链式构建工具定义
pub struct ToolBuilder {
    name: String,
    description: String,
    schema: Option<serde_json::Value>,
}

impl ToolBuilder {
    /// 创建新的工具构建器
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            schema: None,
        }
    }

    /// 设置输入模式
    pub fn schema(mut self, schema: serde_json::Value) -> Self {
        self.schema = Some(schema);
        self
    }

    /// 构建工具定义
    pub fn build(self) -> Tool {
        Tool {
            tool_specification: ToolSpecification {
                name: self.name,
                description: self.description,
                input_schema: InputSchema {
                    json: self.schema.unwrap_or_else(|| {
                        serde_json::json!({
                            "type": "object",
                            "properties": {}
                        })
                    }),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_builder() {
        let tool = Tool::new("read_file", "Read a file from the filesystem")
            .schema(serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "The file path to read"
                    }
                },
                "required": ["path"]
            }))
            .build();

        assert_eq!(tool.name(), "read_file");
        assert_eq!(tool.description(), "Read a file from the filesystem");
    }

    #[test]
    fn test_tool_serialize() {
        let tool = Tool::new("test_tool", "A test tool").build();
        let json = serde_json::to_string(&tool).unwrap();

        assert!(json.contains("\"toolSpecification\""));
        assert!(json.contains("\"name\":\"test_tool\""));
    }

    #[test]
    fn test_tool_result_success() {
        let result = ToolResult::success("tool-123", "Operation completed");

        assert!(result.is_success());
        assert!(!result.is_error);
        assert_eq!(result.status, Some("success".to_string()));
    }

    #[test]
    fn test_tool_result_error() {
        let result = ToolResult::error("tool-456", "File not found");

        assert!(!result.is_success());
        assert!(result.is_error);
        assert_eq!(result.status, Some("error".to_string()));
    }

    #[test]
    fn test_tool_result_serialize() {
        let result = ToolResult::success("tool-789", "Done");
        let json = serde_json::to_string(&result).unwrap();

        assert!(json.contains("\"toolUseId\":\"tool-789\""));
        assert!(json.contains("\"status\":\"success\""));
        // is_error = false 应该被跳过
        assert!(!json.contains("isError"));
    }

    #[test]
    fn test_tool_use_entry() {
        let entry = ToolUseEntry::new("use-123", "read_file")
            .with_input(serde_json::json!({"path": "/test.txt"}));

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"toolUseId\":\"use-123\""));
        assert!(json.contains("\"name\":\"read_file\""));
        assert!(json.contains("\"path\":\"/test.txt\""));
    }

    #[test]
    fn test_input_schema_default() {
        let schema = InputSchema::default();
        assert!(schema.json["type"] == "object");
    }
}
