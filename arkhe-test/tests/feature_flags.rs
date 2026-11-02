//! Feature flag governance tests.
//!
//! Invariant I-T06:
//! Feature flags can NEVER disable mandatory verification gates.
//! `flag ∉ {signature check, hash check, MMR append-only, role separation}`

use arkhe_test::{FeatureFlagPolicy, FlagPolicyError};

#[test]
fn test_feature_flags_cannot_disable_signature_verification() {
    let bad_flag = "security.bypass_signature_check";
    let controls = vec!["signature check bypass".to_string()];

    let result = FeatureFlagPolicy::validate_flag(bad_flag, &controls);
    assert!(result.is_err());
    match result {
        Err(FlagPolicyError::ForbiddenSecurityBypass {
            flag,
            forbidden_aspect,
        }) => {
            assert_eq!(flag, bad_flag);
            assert!(forbidden_aspect.contains("signature"));
        }
        other => panic!("Expected ForbiddenSecurityBypass, got {:?}", other),
    }
}

#[test]
fn test_feature_flags_cannot_disable_hash_verification() {
    let bad_flag = "storage.disable_hash_check";
    let controls = vec!["hash check bypass".to_string()];

    let result = FeatureFlagPolicy::validate_flag(bad_flag, &controls);
    assert!(result.is_err());
    match result {
        Err(FlagPolicyError::ForbiddenSecurityBypass {
            flag,
            forbidden_aspect,
        }) => {
            assert_eq!(flag, bad_flag);
            assert!(forbidden_aspect.contains("hash"));
        }
        other => panic!("Expected ForbiddenSecurityBypass, got {:?}", other),
    }
}

#[test]
fn test_feature_flags_cannot_disable_mmr_append_only() {
    let bad_flag = "audit.override_mmr_append_only";
    let controls = vec!["mmr append-only override".to_string()];

    let result = FeatureFlagPolicy::validate_flag(bad_flag, &controls);
    assert!(result.is_err());
    match result {
        Err(FlagPolicyError::ForbiddenSecurityBypass {
            flag,
            forbidden_aspect,
        }) => {
            assert_eq!(flag, bad_flag);
            assert!(forbidden_aspect.contains("mmr append-only"));
        }
        other => panic!("Expected ForbiddenSecurityBypass, got {:?}", other),
    }
}

#[test]
fn test_feature_flags_cannot_disable_role_separation() {
    let bad_flag = "consensus.bypass_role_separation";
    let controls = vec!["role separation skip".to_string()];

    let result = FeatureFlagPolicy::validate_flag(bad_flag, &controls);
    assert!(result.is_err());
    match result {
        Err(FlagPolicyError::ForbiddenSecurityBypass {
            flag,
            forbidden_aspect,
        }) => {
            assert_eq!(flag, bad_flag);
            assert!(forbidden_aspect.contains("role separation"));
        }
        other => panic!("Expected ForbiddenSecurityBypass, got {:?}", other),
    }
}

#[test]
fn test_valid_experimental_flags_are_accepted() {
    let valid_flag = "network.experimental_transport";
    let controls = vec![
        "Transport selection".to_string(),
        "Buffer sizing".to_string(),
    ];

    assert!(FeatureFlagPolicy::validate_flag(valid_flag, &controls).is_ok());
}
