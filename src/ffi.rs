//! FFI (Foreign Function Interface) module for Go integration
//!
//! This module provides C-compatible exports for the Rust sigma-engine
//! to be used from Go via CGO.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::slice;

use crate::engine::SigmaEngine;
use serde_json::Value;

/// Opaque pointer to SigmaEngine for FFI
#[repr(C)]
pub struct CSigmaEngine {
    engine: Box<SigmaEngine>,
}

/// Result structure for FFI
#[repr(C)]
pub struct CEngineResult {
    pub matched_rules_ptr: *mut usize,
    pub matched_rules_len: usize,
    pub nodes_evaluated: usize,
    pub primitive_evaluations: usize,
    pub error_code: c_int,
}

/// Create a new Sigma engine from rule YAML strings
///
/// # Safety
/// The caller must ensure:
/// - `rules_ptr` points to a valid array of `rules_len` C strings
/// - Each C string in the array is null-terminated
/// - The returned pointer must be freed with `sigma_engine_destroy`
#[no_mangle]
pub unsafe extern "C" fn sigma_engine_create(
    rules_ptr: *const *const c_char,
    rules_len: usize,
) -> *mut std::ffi::c_void {
    if rules_ptr.is_null() || rules_len == 0 {
        return ptr::null_mut();
    }

    // Convert C string array to Rust strings
    let rules_slice = slice::from_raw_parts(rules_ptr, rules_len);
    let mut rule_strings = Vec::with_capacity(rules_len);

    for &rule_ptr in rules_slice {
        if rule_ptr.is_null() {
            return ptr::null_mut();
        }

        let c_str = CStr::from_ptr(rule_ptr);
        match c_str.to_str() {
            Ok(rule_str) => rule_strings.push(rule_str),
            Err(_) => return ptr::null_mut(), // Invalid UTF-8
        }
    }

    // Create engine
    match SigmaEngine::from_rules(&rule_strings) {
        Ok(engine) => {
            let boxed_engine = Box::new(engine);
            let c_engine = CSigmaEngine {
                engine: boxed_engine,
            };
            Box::into_raw(Box::new(c_engine)) as *mut std::ffi::c_void
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Evaluate a JSON event against the sigma engine
///
/// # Safety
/// The caller must ensure:
/// - `engine_ptr` is a valid pointer returned from `sigma_engine_create`
/// - `json_event` is a null-terminated C string containing valid JSON
/// - The returned result must be freed with `sigma_engine_free_result`
#[no_mangle]
pub unsafe extern "C" fn sigma_engine_evaluate(
    engine_ptr: *mut std::ffi::c_void,
    json_event: *const c_char,
) -> CEngineResult {
    let mut result = CEngineResult {
        matched_rules_ptr: ptr::null_mut(),
        matched_rules_len: 0,
        nodes_evaluated: 0,
        primitive_evaluations: 0,
        error_code: 0,
    };

    if engine_ptr.is_null() || json_event.is_null() {
        result.error_code = -1;
        return result;
    }

    let engine_wrapper = &mut *(engine_ptr as *mut CSigmaEngine);
    let engine = &mut engine_wrapper.engine;

    // Convert C string to Rust string
    let c_str = CStr::from_ptr(json_event);
    let json_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            result.error_code = -2; // Invalid UTF-8
            return result;
        }
    };

    // Parse JSON
    let event: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => {
            result.error_code = -3; // Invalid JSON
            return result;
        }
    };

    // Evaluate event
    match engine.evaluate(&event) {
        Ok(eval_result) => {
            result.nodes_evaluated = eval_result.nodes_evaluated;
            result.primitive_evaluations = eval_result.primitive_evaluations;

            if !eval_result.matched_rules.is_empty() {
                // Allocate memory for matched rules
                let matched_rules = eval_result.matched_rules;
                let len = matched_rules.len();
                let ptr = libc::malloc(len * std::mem::size_of::<usize>()) as *mut usize;

                if !ptr.is_null() {
                    let slice = slice::from_raw_parts_mut(ptr, len);
                    for (i, &rule_id) in matched_rules.iter().enumerate() {
                        slice[i] = rule_id as usize;
                    }

                    result.matched_rules_ptr = ptr;
                    result.matched_rules_len = len;
                }
            }

            result.error_code = 0;
        }
        Err(_) => {
            result.error_code = -4; // Evaluation error
        }
    }

    result
}

/// Free the memory allocated for matched rules
///
/// # Safety
/// The caller must ensure:
/// - `matched_rules_ptr` was returned from `sigma_engine_evaluate`
/// - This function is called exactly once for each result
#[no_mangle]
pub unsafe extern "C" fn sigma_engine_free_result(
    matched_rules_ptr: *mut usize,
    matched_rules_len: usize,
) {
    if !matched_rules_ptr.is_null() && matched_rules_len > 0 {
        libc::free(matched_rules_ptr as *mut libc::c_void);
    }
}

/// Destroy a sigma engine and free its memory
///
/// # Safety
/// The caller must ensure:
/// - `engine_ptr` was returned from `sigma_engine_create`
/// - This function is called exactly once for each engine
/// - The engine is not used after this call
#[no_mangle]
pub unsafe extern "C" fn sigma_engine_destroy(engine_ptr: *mut std::ffi::c_void) {
    if !engine_ptr.is_null() {
        let _ = Box::from_raw(engine_ptr as *mut CSigmaEngine);
    }
}

/// Get engine statistics
///
/// # Safety
/// The caller must ensure:
/// - `engine_ptr` is a valid pointer returned from `sigma_engine_create`
/// - `rule_count`, `node_count`, and `primitive_count` are valid pointers
#[no_mangle]
pub unsafe extern "C" fn sigma_engine_stats(
    engine_ptr: *const std::ffi::c_void,
    rule_count: *mut usize,
    node_count: *mut usize,
    primitive_count: *mut usize,
) -> c_int {
    if engine_ptr.is_null()
        || rule_count.is_null()
        || node_count.is_null()
        || primitive_count.is_null()
    {
        return -1;
    }

    let engine_wrapper = &*(engine_ptr as *const CSigmaEngine);
    let engine = &engine_wrapper.engine;

    *rule_count = engine.rule_count();
    *node_count = engine.node_count();
    *primitive_count = engine.primitive_count();

    0 // Success
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_ffi_engine_creation() {
        let rule_yaml = r#"
title: Test Rule
detection:
    selection:
        EventID: 4624
    condition: selection
"#;

        let c_rule = CString::new(rule_yaml).unwrap();
        let rules_ptr = [c_rule.as_ptr()];

        unsafe {
            let engine = sigma_engine_create(rules_ptr.as_ptr(), 1);
            assert!(!engine.is_null());

            sigma_engine_destroy(engine);
        }
    }

    #[test]
    fn test_ffi_engine_evaluation() {
        let rule_yaml = r#"
title: Test Rule
detection:
    selection:
        EventID: 4624
    condition: selection
"#;

        let c_rule = CString::new(rule_yaml).unwrap();
        let rules_ptr = [c_rule.as_ptr()];

        unsafe {
            let engine = sigma_engine_create(rules_ptr.as_ptr(), 1);
            assert!(!engine.is_null());

            let event_json = r#"{"EventID": "4624"}"#;
            let c_event = CString::new(event_json).unwrap();

            let result = sigma_engine_evaluate(engine, c_event.as_ptr());
            assert_eq!(result.error_code, 0);
            assert!(result.nodes_evaluated > 0);

            if !result.matched_rules_ptr.is_null() {
                sigma_engine_free_result(result.matched_rules_ptr, result.matched_rules_len);
            }

            sigma_engine_destroy(engine);
        }
    }

    #[test]
    fn test_ffi_engine_stats() {
        let rule_yaml = r#"
title: Test Rule
detection:
    selection:
        EventID: 4624
    condition: selection
"#;

        let c_rule = CString::new(rule_yaml).unwrap();
        let rules_ptr = [c_rule.as_ptr()];

        unsafe {
            let engine = sigma_engine_create(rules_ptr.as_ptr(), 1);
            assert!(!engine.is_null());

            let mut rule_count = 0;
            let mut node_count = 0;
            let mut primitive_count = 0;

            let result = sigma_engine_stats(
                engine,
                &mut rule_count,
                &mut node_count,
                &mut primitive_count,
            );

            assert_eq!(result, 0); // Success
            assert_eq!(rule_count, 1);
            assert!(node_count > 0);
            assert!(primitive_count > 0);

            sigma_engine_destroy(engine);
        }
    }
}
