//! Testes E2E de fail-closed.

use std::sync::Arc;

use arkhe_code_review_agents::{
    AgentError, AgentKind, MockLogicAgent, MockSecurityAgent, ReviewAgent,
};
use arkhe_code_review_context::ReviewContext;
use arkhe_code_review_core::{ReviewConfig, ReviewOrchestrator};
use arkhe_code_review_diff::Diff;
use arkhe_code_review_static::{Finding, NoUnwrapAnalyzer};

const DIFF: &str = concat!(
    "diff --git a/x.rs b/x.rs\n",
    "--- a/x.rs\n",
    "+++ b/x.rs\n",
    "@@ -1,3 +1,5 @@\n",
    " pub fn test() {\n",
    "-    todo!()\n",
    "+    let x = g().unwrap();\n",
    "+    if x == None { panic!() }\n",
    "+    let q = format!(\"SELECT * FROM users WHERE id = {}\", id);\n",
    " }\n"
);

fn orchestrator(require_cross: bool) -> ReviewOrchestrator {
    ReviewOrchestrator::new(
        vec![Box::new(NoUnwrapAnalyzer)],
        vec![
            Arc::new(MockLogicAgent::new("claude-opus")),
            Arc::new(MockSecurityAgent::new("gpt-5")),
        ],
        ReviewConfig {
            require_cross_model: require_cross,
            ..Default::default()
        },
    )
}

#[tokio::test]
async fn empty_diff_blocks() {
    let o = orchestrator(true);
    assert!(o.review("", ReviewContext::new()).await.is_err());
}

#[tokio::test]
async fn cross_model_fatal_e2e() {
    let o = ReviewOrchestrator::new(
        vec![],
        vec![Arc::new(MockLogicAgent::new("only-one"))],
        ReviewConfig {
            require_cross_model: true,
            ..Default::default()
        },
    );
    assert!(o.review(DIFF, ReviewContext::new()).await.is_err());
}

#[tokio::test]
async fn happy_path() {
    let o = orchestrator(true);
    let r = o
        .review(DIFF, ReviewContext::new())
        .await
        .unwrap_or_else(|e| panic!("failed: {:?}", e));
    assert_ne!(r.record_hash, [0u8; 32]);
    assert_eq!(r.models_used.len(), 2);

    assert!(!r.static_only);
}

#[tokio::test]
async fn static_only_reported() {
    let o = ReviewOrchestrator::new(
        vec![Box::new(NoUnwrapAnalyzer)],
        vec![],
        ReviewConfig {
            require_cross_model: true,
            ..Default::default()
        },
    );
    let r = o
        .review(DIFF, ReviewContext::new())
        .await
        .unwrap_or_else(|e| panic!("failed: {:?}", e));
    assert!(r.static_only);
}

#[tokio::test]
async fn agent_failure_does_not_block() {
    #[derive(Debug)]
    struct FailingAgent;
    #[async_trait::async_trait]
    impl ReviewAgent for FailingAgent {
        async fn review(&self, _: &Diff, _: &ReviewContext) -> Result<Vec<Finding>, AgentError> {
            Err(AgentError::Backend("simulated".into()))
        }
        fn kind(&self) -> AgentKind {
            AgentKind::Logic
        }
        fn model(&self) -> &str {
            "failing"
        }
    }

    let o = ReviewOrchestrator::new(
        vec![Box::new(NoUnwrapAnalyzer)],
        vec![
            Arc::new(FailingAgent),
            Arc::new(MockLogicAgent::new("claude-opus")),
            Arc::new(MockSecurityAgent::new("gpt-5")),
        ],
        ReviewConfig::default(),
    );
    let r = o
        .review(DIFF, ReviewContext::new())
        .await
        .unwrap_or_else(|e| panic!("failed: {:?}", e));
    assert_eq!(r.agent_errors.len(), 1);
}

#[tokio::test]
async fn agent_panic_does_not_block() {
    #[derive(Debug)]
    struct PanickingAgent;
    #[async_trait::async_trait]
    impl ReviewAgent for PanickingAgent {
        async fn review(&self, _: &Diff, _: &ReviewContext) -> Result<Vec<Finding>, AgentError> {
            panic!("simulated panic");
        }
        fn kind(&self) -> AgentKind {
            AgentKind::Security
        }
        fn model(&self) -> &str {
            "panicking"
        }
    }

    let o = ReviewOrchestrator::new(
        vec![Box::new(NoUnwrapAnalyzer)],
        vec![
            Arc::new(PanickingAgent),
            Arc::new(MockLogicAgent::new("claude-opus")),
        ],
        ReviewConfig {
            require_cross_model: false,
            ..Default::default()
        },
    );
    let r = o
        .review(DIFF, ReviewContext::new())
        .await
        .unwrap_or_else(|e| panic!("failed: {:?}", e));
    assert_eq!(r.agent_panics.len(), 1);
}
