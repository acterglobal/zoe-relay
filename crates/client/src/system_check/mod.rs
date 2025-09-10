//! System Check API for comprehensive client testing
//!
//! This module provides a comprehensive system check API that can test various
//! aspects of the Zoe client functionality including connectivity, storage,
//! and blob services. The API is designed to be used both from CLI tools
//! and programmatically via FRB bindings.

use crate::{Client, ClientError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::info;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

pub mod blob_service;
pub mod connectivity;
pub mod offline_blob;
pub mod offline_storage;
pub mod storage;
pub mod synchronization;

#[cfg(test)]
mod tests;

/// Level of diagnostic message
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "frb-api", frb)]
pub enum DiagnosticLevel {
    Error,
    Warning,
}

/// A diagnostic message captured during system check
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "frb-api", frb)]
pub struct DiagnosticMessage {
    pub level: DiagnosticLevel,
    pub message: String,
}

/// Trait for collecting diagnostic messages
pub trait DiagnosticCollector: Send + Sync {
    fn add_error(&mut self, message: String);
    fn add_warning(&mut self, message: String);
}

/// Overall outcome of system check including test results and diagnostics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "frb-api", frb)]
pub struct SystemCheckOutcome {
    pub test_results: SystemCheckResults,
    pub diagnostics: Vec<DiagnosticMessage>,
    pub success: bool,
    pub has_errors: bool,
    pub has_warnings: bool,
}

/// Configuration for system check operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "frb-api", frb(opaque))]
pub struct SystemCheckConfig {
    /// Size of test data for blob service tests (in bytes)
    pub blob_test_size: usize,
    /// Number of test messages for storage tests
    pub storage_test_count: u32,
    /// Timeout for individual test operations
    pub operation_timeout: Duration,
    /// Whether to skip blob service tests
    pub skip_blob_tests: bool,
    /// Whether to skip storage tests
    pub skip_storage_tests: bool,
    /// Whether to skip connectivity tests
    pub skip_connectivity_tests: bool,
    /// Whether to run offline tests first (before establishing relay connection)
    pub run_offline_tests: bool,
    /// Whether to verify sync after establishing connection
    pub verify_sync: bool,
    /// Number of offline messages to create for sync verification
    pub offline_message_count: u32,
    /// Size of offline blob data for sync verification
    pub offline_blob_size: usize,
}

impl Default for SystemCheckConfig {
    fn default() -> Self {
        Self {
            blob_test_size: 1024 * 1024, // 1MB
            storage_test_count: 3,
            operation_timeout: Duration::from_secs(30),
            skip_blob_tests: false,
            skip_storage_tests: false,
            skip_connectivity_tests: false,
            run_offline_tests: true,
            verify_sync: true,
            offline_message_count: 2,
            offline_blob_size: 64 * 1024, // 64KB for offline tests
        }
    }
}

/// Result of a single system check test
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "frb-api", frb)]
pub enum TestResult {
    /// Test passed successfully
    Passed,
    /// Test failed with error message
    Failed { error: String },
    /// Test was skipped
    Skipped,
}

impl TestResult {
    pub fn is_passed(&self) -> bool {
        matches!(self, TestResult::Passed)
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, TestResult::Failed { .. })
    }

    pub fn is_skipped(&self) -> bool {
        matches!(self, TestResult::Skipped)
    }
}

/// Detailed information about a test execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "frb-api", frb(opaque))]
pub struct TestInfo {
    /// Name of the test
    pub name: String,
    /// Test result
    pub result: TestResult,
    /// Duration of the test execution
    pub duration: Duration,
    /// Additional details about the test execution
    pub details: Vec<String>,
    /// Timestamp when the test started (as seconds since UNIX epoch)
    #[serde(with = "instant_serde")]
    pub started_at: Instant,
}

mod instant_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    pub fn serialize<S>(instant: &Instant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert to system time for serialization
        let system_time = SystemTime::now() - instant.elapsed();
        let duration_since_epoch = system_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        duration_since_epoch.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Instant, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        let system_time = UNIX_EPOCH + Duration::from_secs(secs);
        let now = SystemTime::now();
        let instant_offset = now.duration_since(system_time).unwrap_or(Duration::ZERO);
        Ok(Instant::now() - instant_offset)
    }
}

impl TestInfo {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            result: TestResult::Skipped,
            duration: Duration::ZERO,
            details: Vec::new(),
            started_at: Instant::now(),
        }
    }

    pub fn with_result(mut self, result: TestResult) -> Self {
        self.result = result;
        self.duration = self.started_at.elapsed();
        self
    }

    pub fn add_detail(&mut self, detail: impl Into<String>) {
        self.details.push(detail.into());
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.add_detail(detail);
        self
    }
}

/// Categories of system check tests
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "frb-api", frb)]
pub enum TestCategory {
    /// Offline storage tests (without relay connection)
    OfflineStorage,
    /// Offline blob service tests (without relay connection)
    OfflineBlob,
    /// Server connectivity and handshake tests
    Connectivity,
    /// Online message storage and retrieval tests
    Storage,
    /// Online blob service upload/download tests
    BlobService,
    /// Synchronization verification tests
    Synchronization,
}

impl TestCategory {
    pub fn name(&self) -> &'static str {
        match self {
            TestCategory::OfflineStorage => "Offline Storage",
            TestCategory::OfflineBlob => "Offline Blob Service",
            TestCategory::Connectivity => "Server Connectivity",
            TestCategory::Storage => "Online Storage",
            TestCategory::BlobService => "Online Blob Service",
            TestCategory::Synchronization => "Synchronization",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            TestCategory::OfflineStorage => "💽",
            TestCategory::OfflineBlob => "📁",
            TestCategory::Connectivity => "🚀",
            TestCategory::Storage => "💾",
            TestCategory::BlobService => "📦",
            TestCategory::Synchronization => "🔄",
        }
    }
}

/// Comprehensive results of all system check tests
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "frb-api", frb(opaque))]
pub struct SystemCheckResults {
    /// Results organized by test category
    pub results: BTreeMap<TestCategory, Vec<TestInfo>>,
    /// Overall duration of all tests
    pub total_duration: Duration,
    /// Timestamp when the system check started
    #[serde(with = "instant_serde")]
    pub started_at: Instant,
    /// Configuration used for the tests
    pub config: SystemCheckConfig,
}

impl SystemCheckResults {
    pub fn new(config: SystemCheckConfig) -> Self {
        Self {
            results: BTreeMap::new(),
            total_duration: Duration::ZERO,
            started_at: Instant::now(),
            config,
        }
    }

    /// Add a test result to the specified category
    pub fn add_test(&mut self, category: TestCategory, test: TestInfo) {
        self.results.entry(category).or_default().push(test);
    }

    /// Finalize the results by calculating total duration
    pub fn finalize(&mut self) {
        self.total_duration = self.started_at.elapsed();
    }

    /// Get the overall success status
    pub fn is_success(&self) -> bool {
        self.results.values().all(|tests| {
            tests
                .iter()
                .all(|test| test.result.is_passed() || test.result.is_skipped())
        })
    }

    /// Get count of passed tests
    pub fn passed_count(&self) -> usize {
        self.results
            .values()
            .flat_map(|tests| tests.iter())
            .filter(|test| test.result.is_passed())
            .count()
    }

    /// Get count of failed tests
    pub fn failed_count(&self) -> usize {
        self.results
            .values()
            .flat_map(|tests| tests.iter())
            .filter(|test| test.result.is_failed())
            .count()
    }

    /// Get count of skipped tests
    pub fn skipped_count(&self) -> usize {
        self.results
            .values()
            .flat_map(|tests| tests.iter())
            .filter(|test| test.result.is_skipped())
            .count()
    }

    /// Get total count of tests
    pub fn total_count(&self) -> usize {
        self.results.values().flat_map(|tests| tests.iter()).count()
    }

    /// Get the first failed test, if any
    pub fn first_failure(&self) -> Option<&TestInfo> {
        self.results
            .values()
            .flat_map(|tests| tests.iter())
            .find(|test| test.result.is_failed())
    }

    /// Get results for a specific category
    pub fn get_category_results(&self, category: TestCategory) -> Option<&Vec<TestInfo>> {
        self.results.get(&category)
    }

    /// Check if a specific category has any failures
    pub fn category_has_failures(&self, category: TestCategory) -> bool {
        self.results
            .get(&category)
            .map(|tests| tests.iter().any(|test| test.result.is_failed()))
            .unwrap_or(false)
    }
}

/// Main system check runner
#[cfg_attr(feature = "frb-api", frb(opaque))]
pub struct SystemCheck {
    client: Client,
    config: SystemCheckConfig,
}

impl SystemCheck {
    /// Create a new system check instance
    pub fn new(client: Client, config: SystemCheckConfig) -> Self {
        Self { client, config }
    }

    /// Create a new system check instance with default configuration
    pub fn with_defaults(client: Client) -> Self {
        Self::new(client, SystemCheckConfig::default())
    }

    /// Run all enabled system checks in the comprehensive flow:
    /// 1. Offline tests (if enabled)
    /// 2. Connectivity tests
    /// 3. Online tests
    /// 4. Synchronization verification (if enabled)
    pub async fn run_all(&self) -> Result<SystemCheckResults, ClientError> {
        let mut results = SystemCheckResults::new(self.config.clone());

        // Phase 1: Offline tests (before establishing relay connection)
        if self.config.run_offline_tests {
            info!("🔧 Phase 1: Running offline tests...");

            if !self.config.skip_storage_tests {
                let offline_storage_results =
                    offline_storage::run_tests(&self.client, &self.config).await;
                for test in offline_storage_results {
                    results.add_test(TestCategory::OfflineStorage, test);
                }
            }

            if !self.config.skip_blob_tests {
                let offline_blob_results =
                    offline_blob::run_tests(&self.client, &self.config).await;
                for test in offline_blob_results {
                    results.add_test(TestCategory::OfflineBlob, test);
                }
            }
        }

        // Phase 2: Connectivity tests (establish relay connection)
        if !self.config.skip_connectivity_tests {
            info!("🚀 Phase 2: Establishing connectivity...");
            let connectivity_results = connectivity::run_tests(&self.client, &self.config).await;
            for test in connectivity_results {
                results.add_test(TestCategory::Connectivity, test);
            }
        }

        // Phase 3: Online tests (with relay connection)
        info!("🌐 Phase 3: Running online tests...");

        if !self.config.skip_storage_tests {
            let storage_results = storage::run_tests(&self.client, &self.config).await;
            for test in storage_results {
                results.add_test(TestCategory::Storage, test);
            }
        }

        if !self.config.skip_blob_tests {
            let blob_results = blob_service::run_tests(&self.client, &self.config).await;
            for test in blob_results {
                results.add_test(TestCategory::BlobService, test);
            }
        }

        // Phase 4: Synchronization verification (verify offline data synced)
        if self.config.verify_sync && self.config.run_offline_tests {
            info!("🔄 Phase 4: Verifying synchronization...");
            let sync_results = synchronization::run_tests(&self.client, &self.config).await;
            for test in sync_results {
                results.add_test(TestCategory::Synchronization, test);
            }
        }

        results.finalize();
        Ok(results)
    }

    /// Run only connectivity tests
    pub async fn run_connectivity_tests(&self) -> Result<Vec<TestInfo>, ClientError> {
        Ok(connectivity::run_tests(&self.client, &self.config).await)
    }

    /// Run only storage tests
    pub async fn run_storage_tests(&self) -> Result<Vec<TestInfo>, ClientError> {
        Ok(storage::run_tests(&self.client, &self.config).await)
    }

    /// Run only blob service tests
    pub async fn run_blob_service_tests(&self) -> Result<Vec<TestInfo>, ClientError> {
        Ok(blob_service::run_tests(&self.client, &self.config).await)
    }

    /// Run only offline storage tests
    pub async fn run_offline_storage_tests(&self) -> Result<Vec<TestInfo>, ClientError> {
        Ok(offline_storage::run_tests(&self.client, &self.config).await)
    }

    /// Run only offline blob tests
    pub async fn run_offline_blob_tests(&self) -> Result<Vec<TestInfo>, ClientError> {
        Ok(offline_blob::run_tests(&self.client, &self.config).await)
    }

    /// Run only synchronization tests
    pub async fn run_synchronization_tests(&self) -> Result<Vec<TestInfo>, ClientError> {
        Ok(synchronization::run_tests(&self.client, &self.config).await)
    }

    /// Run tests for a specific category
    pub async fn run_category_tests(
        &self,
        category: TestCategory,
    ) -> Result<Vec<TestInfo>, ClientError> {
        match category {
            TestCategory::OfflineStorage => self.run_offline_storage_tests().await,
            TestCategory::OfflineBlob => self.run_offline_blob_tests().await,
            TestCategory::Connectivity => self.run_connectivity_tests().await,
            TestCategory::Storage => self.run_storage_tests().await,
            TestCategory::BlobService => self.run_blob_service_tests().await,
            TestCategory::Synchronization => self.run_synchronization_tests().await,
        }
    }
}

#[cfg_attr(feature = "frb-api", frb)]
impl SystemCheckConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the blob test size
    pub fn with_blob_test_size(mut self, size: usize) -> Self {
        self.blob_test_size = size;
        self
    }

    /// Set the storage test count
    pub fn with_storage_test_count(mut self, count: u32) -> Self {
        self.storage_test_count = count;
        self
    }

    /// Set the operation timeout
    pub fn with_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.operation_timeout = Duration::from_secs(timeout_secs);
        self
    }

    /// Skip blob service tests
    pub fn skip_blob_tests(mut self) -> Self {
        self.skip_blob_tests = true;
        self
    }

    /// Skip storage tests
    pub fn skip_storage_tests(mut self) -> Self {
        self.skip_storage_tests = true;
        self
    }

    /// Skip connectivity tests
    pub fn skip_connectivity_tests(mut self) -> Self {
        self.skip_connectivity_tests = true;
        self
    }

    /// Enable/disable offline tests
    pub fn with_offline_tests(mut self, enabled: bool) -> Self {
        self.run_offline_tests = enabled;
        self
    }

    /// Enable/disable sync verification
    pub fn with_sync_verification(mut self, enabled: bool) -> Self {
        self.verify_sync = enabled;
        self
    }

    /// Set the number of offline messages for sync verification
    pub fn with_offline_message_count(mut self, count: u32) -> Self {
        self.offline_message_count = count;
        self
    }

    /// Set the size of offline blob data for sync verification
    pub fn with_offline_blob_size(mut self, size: usize) -> Self {
        self.offline_blob_size = size;
        self
    }
}

#[cfg_attr(feature = "frb-api", frb)]
impl SystemCheck {
    /// Create a system check instance for FRB API
    pub fn create(client: Client) -> Self {
        Self::with_defaults(client)
    }

    /// Create a system check instance with custom configuration for FRB API
    pub fn create_with_config(client: Client, config: SystemCheckConfig) -> Self {
        Self::new(client, config)
    }
}

/// Enhanced diagnostic collector that can extract messages
pub trait ExtractableDiagnosticCollector: DiagnosticCollector {
    fn extract_messages(&self) -> (Vec<DiagnosticMessage>, bool, bool);
}

/// Run system check with custom diagnostic collection
///
/// This is the main reusable function that can be used by both CLI and FRB API.
/// It sets up tracing with the provided diagnostic collector and runs the system check.
pub async fn run_system_check_with_diagnostics<F, D>(
    client: Client,
    config: SystemCheckConfig,
    diagnostic_collector: Arc<Mutex<D>>,
    setup_tracing: F,
) -> Result<SystemCheckOutcome, ClientError>
where
    F: FnOnce(Arc<Mutex<D>>) -> Result<(), Box<dyn std::error::Error + Send + Sync>>,
    D: ExtractableDiagnosticCollector + 'static,
{
    // Set up tracing with the provided diagnostic collector
    setup_tracing(diagnostic_collector.clone())
        .map_err(|e| ClientError::Generic(format!("Failed to setup tracing: {}", e)))?;

    // Run the system check
    let system_check = SystemCheck::new(client, config);
    let test_results = system_check.run_all().await?;

    // Extract diagnostics
    let (diagnostics, has_errors, has_warnings) = {
        let collector = diagnostic_collector.lock().unwrap();
        collector.extract_messages()
    };

    let success = test_results.is_success() && !has_errors;

    Ok(SystemCheckOutcome {
        test_results,
        diagnostics,
        success,
        has_errors,
        has_warnings,
    })
}
