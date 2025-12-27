//! 辅助结构体定义
//!
//! 定义 Kiro API 使用的辅助结构体，用于响应事件的嵌套字段

use serde::{Deserialize, Serialize};

use super::enums::UserIntent;

/// 内容范围标记
///
/// 用于标记内容在响应中的位置范围
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentSpan {
    /// 起始位置
    pub start: i32,
    /// 结束位置
    pub end: i32,
}

impl ContentSpan {
    /// 创建新的内容范围
    pub fn new(start: i32, end: i32) -> Self {
        Self { start, end }
    }

    /// 获取范围长度
    pub fn len(&self) -> i32 {
        self.end - self.start
    }

    /// 判断范围是否为空
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

/// 补充网页链接
///
/// 助手响应中包含的相关网页链接
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupplementaryWebLink {
    /// 链接 URL
    pub url: String,
    /// 链接标题
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// 链接摘要
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// 相关性评分
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
}

impl SupplementaryWebLink {
    /// 创建新的网页链接
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            title: None,
            snippet: None,
            score: None,
        }
    }

    /// 设置标题
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// 设置摘要
    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }

    /// 设置评分
    pub fn with_score(mut self, score: f64) -> Self {
        self.score = Some(score);
        self
    }
}

/// 最相关的错过的替代方案
///
/// 当存在更好的替代方案时，提供相关信息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MostRelevantMissedAlternative {
    /// 替代方案 URL
    pub url: String,
    /// 许可证名称
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_name: Option<String>,
    /// 仓库名称
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
}

impl MostRelevantMissedAlternative {
    /// 创建新的替代方案
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            license_name: None,
            repository: None,
        }
    }
}

/// 代码引用
///
/// 助手响应中引用的代码来源信息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
    /// 许可证名称
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_name: Option<String>,
    /// 仓库名称
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// 引用 URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// 附加信息
    #[serde(skip_serializing_if = "Option::is_none")]
    pub information: Option<String>,
    /// 推荐内容在响应中的位置范围
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation_content_span: Option<ContentSpan>,
    /// 最相关的错过的替代方案
    #[serde(skip_serializing_if = "Option::is_none")]
    pub most_relevant_missed_alternative: Option<MostRelevantMissedAlternative>,
}

impl Reference {
    /// 创建新的空引用
    pub fn new() -> Self {
        Self {
            license_name: None,
            repository: None,
            url: None,
            information: None,
            recommendation_content_span: None,
            most_relevant_missed_alternative: None,
        }
    }

    /// 设置许可证名称
    pub fn with_license_name(mut self, name: impl Into<String>) -> Self {
        self.license_name = Some(name.into());
        self
    }

    /// 设置仓库名称
    pub fn with_repository(mut self, repo: impl Into<String>) -> Self {
        self.repository = Some(repo.into());
        self
    }

    /// 设置 URL
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
}

impl Default for Reference {
    fn default() -> Self {
        Self::new()
    }
}

/// 后续提示
///
/// 助手建议的后续对话提示
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FollowupPrompt {
    /// 提示内容
    pub content: String,
    /// 用户意图
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_intent: Option<UserIntent>,
}

impl FollowupPrompt {
    /// 创建新的后续提示
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            user_intent: None,
        }
    }

    /// 设置用户意图
    pub fn with_user_intent(mut self, intent: UserIntent) -> Self {
        self.user_intent = Some(intent);
        self
    }
}

/// 编程语言
///
/// 表示代码的编程语言信息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgrammingLanguage {
    /// 语言名称
    pub language_name: String,
}

impl ProgrammingLanguage {
    /// 创建新的编程语言
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            language_name: name.into(),
        }
    }
}

/// 定制化配置
///
/// 自定义模型配置信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customization {
    /// ARN (Amazon Resource Name)
    pub arn: String,
    /// 配置名称
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Customization {
    /// 创建新的定制化配置
    pub fn new(arn: impl Into<String>) -> Self {
        Self {
            arn: arn.into(),
            name: None,
        }
    }

    /// 设置名称
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// 代码查询
///
/// 代码查询信息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeQuery {
    /// 代码查询 ID
    pub code_query_id: String,
    /// 编程语言
    #[serde(skip_serializing_if = "Option::is_none")]
    pub programming_language: Option<ProgrammingLanguage>,
    /// 用户输入消息 ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_input_message_id: Option<String>,
}

impl CodeQuery {
    /// 创建新的代码查询
    pub fn new(code_query_id: impl Into<String>) -> Self {
        Self {
            code_query_id: code_query_id.into(),
            programming_language: None,
            user_input_message_id: None,
        }
    }

    /// 设置编程语言
    pub fn with_programming_language(mut self, lang: ProgrammingLanguage) -> Self {
        self.programming_language = Some(lang);
        self
    }

    /// 设置用户输入消息 ID
    pub fn with_user_input_message_id(mut self, id: impl Into<String>) -> Self {
        self.user_input_message_id = Some(id.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_span() {
        let span = ContentSpan::new(10, 20);
        assert_eq!(span.len(), 10);
        assert!(!span.is_empty());

        let empty_span = ContentSpan::new(5, 5);
        assert!(empty_span.is_empty());
    }

    #[test]
    fn test_supplementary_web_link_serialize() {
        let link = SupplementaryWebLink::new("https://example.com")
            .with_title("Example")
            .with_score(0.95);

        let json = serde_json::to_string(&link).unwrap();
        assert!(json.contains("\"url\":\"https://example.com\""));
        assert!(json.contains("\"title\":\"Example\""));
        assert!(json.contains("\"score\":0.95"));
    }

    #[test]
    fn test_supplementary_web_link_deserialize() {
        let json = r#"{"url":"https://test.com","title":"Test","snippet":"A test link","score":0.8}"#;
        let link: SupplementaryWebLink = serde_json::from_str(json).unwrap();
        assert_eq!(link.url, "https://test.com");
        assert_eq!(link.title, Some("Test".to_string()));
        assert_eq!(link.snippet, Some("A test link".to_string()));
        assert_eq!(link.score, Some(0.8));
    }

    #[test]
    fn test_reference_builder() {
        let reference = Reference::new()
            .with_license_name("MIT")
            .with_repository("example/repo")
            .with_url("https://github.com/example/repo");

        assert_eq!(reference.license_name, Some("MIT".to_string()));
        assert_eq!(reference.repository, Some("example/repo".to_string()));
    }

    #[test]
    fn test_followup_prompt_serialize() {
        let prompt = FollowupPrompt::new("How can I improve this code?")
            .with_user_intent(UserIntent::ImproveCode);

        let json = serde_json::to_string(&prompt).unwrap();
        assert!(json.contains("\"content\":\"How can I improve this code?\""));
        assert!(json.contains("\"userIntent\":\"IMPROVE_CODE\""));
    }

    #[test]
    fn test_programming_language() {
        let lang = ProgrammingLanguage::new("rust");
        let json = serde_json::to_string(&lang).unwrap();
        assert_eq!(json, r#"{"languageName":"rust"}"#);
    }

    #[test]
    fn test_code_query() {
        let query = CodeQuery::new("query-123")
            .with_programming_language(ProgrammingLanguage::new("python"))
            .with_user_input_message_id("msg-456");

        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("\"codeQueryId\":\"query-123\""));
        assert!(json.contains("\"languageName\":\"python\""));
    }
}
