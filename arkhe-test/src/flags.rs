//! Feature flag policy governance.
//!
//! Invariant I-T06 rule:
//! `flag ∉ {signature check, hash check, MMR append-only, role separation}`
//! Feature flags may gate alternative behaviors or enable experimental modes,
//! but can NEVER weaken, bypass, or disable mandatory security verifications.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FlagPolicyError {
    #[error(
        "Forbidden security bypass flag detected: flag '{flag}' cannot alter '{forbidden_aspect}'"
    )]
    ForbiddenSecurityBypass {
        flag: String,
        forbidden_aspect: String,
    },
    #[error("Unknown or malformed flag policy: {0}")]
    MalformedPolicy(String),
    #[error("Flag '{0}' violates fail-closed default")]
    ViolatesFailClosed(String),
}

/// Permitted feature flag entry from policies/flags.toml
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureFlagSpec {
    pub name: String,
    pub description: String,
    pub can_control: Vec<String>,
    pub cannot_control: Vec<String>,
    pub default_enabled: bool,
}

/// Complete feature flag policy definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureFlagPolicy {
    pub flags: BTreeMap<String, FeatureFlagSpec>,
}

impl FeatureFlagPolicy {
    /// Forbidden keywords that a flag can never disable or bypass.
    pub const FORBIDDEN_ASPECTS: &'static [&'static str] = &[
        "signature check",
        "hash check",
        "mmr append-only",
        "role separation",
        "chunk validation",
        "manifest validation",
        "offline validity",
        "human canonization",
        "device attestation",
    ];

    /// Load default canonical policy according to Arkhe specification.
    pub fn standard() -> Self {
        let mut flags = BTreeMap::new();
        flags.insert(
            "network.experimental_transport".to_string(),
            FeatureFlagSpec {
                name: "network.experimental_transport".to_string(),
                description: "Alternative network transport protocol".to_string(),
                can_control: vec![
                    "Transport selection".to_string(),
                    "Buffer sizing".to_string(),
                ],
                cannot_control: vec!["Validação de chunk".to_string(), "hash check".to_string()],
                default_enabled: false,
            },
        );
        flags.insert(
            "moe.receipt_tree".to_string(),
            FeatureFlagSpec {
                name: "moe.receipt_tree".to_string(),
                description: "Activation of hierarchical receipt tree".to_string(),
                can_control: vec!["Receipt aggregation layout".to_string()],
                cannot_control: vec![
                    "Assinatura dos recibos".to_string(),
                    "signature check".to_string(),
                ],
                default_enabled: false,
            },
        );
        flags.insert(
            "audit.bundle_v2".to_string(),
            FeatureFlagSpec {
                name: "audit.bundle_v2".to_string(),
                description: "Experimental bundle layout v2".to_string(),
                can_control: vec!["Bundle format serialization".to_string()],
                cannot_control: vec![
                    "Append-only da MMR".to_string(),
                    "mmr append-only".to_string(),
                ],
                default_enabled: false,
            },
        );
        flags.insert(
            "cal.anchor_batching".to_string(),
            FeatureFlagSpec {
                name: "cal.anchor_batching".to_string(),
                description: "Batching frequency for state anchoring".to_string(),
                can_control: vec!["Anchor batch window (ms)".to_string()],
                cannot_control: vec![
                    "Validade offline da evidência".to_string(),
                    "hash check".to_string(),
                ],
                default_enabled: false,
            },
        );
        flags.insert(
            "inference.zk_sampling".to_string(),
            FeatureFlagSpec {
                name: "inference.zk_sampling".to_string(),
                description: "Adaptive sampling rate for ZK proofs".to_string(),
                can_control: vec!["Sampling percentage".to_string()],
                cannot_control: vec![
                    "Verificação mínima obrigatória".to_string(),
                    "signature check".to_string(),
                ],
                default_enabled: false,
            },
        );
        flags.insert(
            "mcp.action_tools".to_string(),
            FeatureFlagSpec {
                name: "mcp.action_tools".to_string(),
                description: "Exposes MCP tools requiring write authorization".to_string(),
                can_control: vec!["Exposure of write tool definitions".to_string()],
                cannot_control: vec![
                    "Mandato assinado".to_string(),
                    "signature check".to_string(),
                ],
                default_enabled: false,
            },
        );
        flags.insert(
            "governance.proposals".to_string(),
            FeatureFlagSpec {
                name: "governance.proposals".to_string(),
                description: "Submits proposals into governance pipeline".to_string(),
                can_control: vec!["Autonomous proposal drafting".to_string()],
                cannot_control: vec![
                    "Canonificação humana".to_string(),
                    "human canonization".to_string(),
                ],
                default_enabled: false,
            },
        );

        Self { flags }
    }

    /// Validates an incoming configuration or flag definition.
    /// Returns Err if any flag attempts to control or disable a forbidden security aspect.
    pub fn validate_flag(
        flag_name: &str,
        intended_controls: &[String],
    ) -> Result<(), FlagPolicyError> {
        let flag_lower = flag_name.to_lowercase();
        for aspect in Self::FORBIDDEN_ASPECTS {
            if flag_lower.contains(&aspect.replace(' ', "_"))
                || flag_lower.contains(&aspect.replace('-', "_"))
                || flag_lower.contains(aspect)
            {
                return Err(FlagPolicyError::ForbiddenSecurityBypass {
                    flag: flag_name.to_string(),
                    forbidden_aspect: aspect.to_string(),
                });
            }
        }

        for control in intended_controls {
            let ctrl_lower = control.to_lowercase();
            for aspect in Self::FORBIDDEN_ASPECTS {
                if ctrl_lower.contains(aspect) {
                    return Err(FlagPolicyError::ForbiddenSecurityBypass {
                        flag: flag_name.to_string(),
                        forbidden_aspect: aspect.to_string(),
                    });
                }
            }
        }

        Ok(())
    }
}
