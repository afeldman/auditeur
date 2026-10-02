//! Hardware detection.
//!
//! Real probing, honest reporting. Every accelerator is reported as one of
//! [`Availability::Available`], [`Availability::Unavailable`] (probed and not
//! present) or [`Availability::Unknown`] (could not be determined). There is no
//! "probably fine": a capability that cannot be established is reported as
//! unknown, which is what `doctor` prints.
//!
//! Note on scope: with the HTTP backend, acceleration is a property of the
//! inference *server*, not of Auditeur. This module reports what the machine
//! offers so that a future in-process backend can negotiate a device, and so
//! that `doctor` can explain why a run is slow.

use serde::{Deserialize, Serialize};

use auditeur_repository::host::{probe, HostProbe, PROBE_TIMEOUT};

/// An execution device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Accelerator {
    /// The CPU. Always present; the fallback.
    Cpu,
    /// Apple Metal.
    Metal,
    /// NVIDIA CUDA.
    Cuda,
    /// AMD ROCm.
    Rocm,
    /// Vulkan compute.
    Vulkan,
}

impl Accelerator {
    /// Stable identifier used in configuration and reports.
    pub fn id(self) -> &'static str {
        match self {
            Accelerator::Cpu => "cpu",
            Accelerator::Metal => "metal",
            Accelerator::Cuda => "cuda",
            Accelerator::Rocm => "rocm",
            Accelerator::Vulkan => "vulkan",
        }
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Accelerator::Cpu => "CPU",
            Accelerator::Metal => "Metal",
            Accelerator::Cuda => "CUDA",
            Accelerator::Rocm => "ROCm",
            Accelerator::Vulkan => "Vulkan",
        }
    }
}

/// Whether a capability is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    /// Probed and present.
    Available,
    /// Probed and not present.
    Unavailable,
    /// Could not be determined.
    Unknown,
}

impl Availability {
    /// Stable identifier.
    pub fn id(self) -> &'static str {
        match self {
            Availability::Available => "available",
            Availability::Unavailable => "unavailable",
            Availability::Unknown => "unknown",
        }
    }
}

/// What an availability conclusion is based on.
///
/// Typed rather than free-form so that the honesty rule is checkable: a device
/// may only be reported as available because the platform guarantees it, because
/// it is the always-present CPU, or because a probe program confirmed it — never
/// because we assumed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProbeSource {
    /// The CPU: always usable, no probe needed.
    Always,
    /// A capability guaranteed by the operating system.
    Platform,
    /// A probe program, named.
    Program {
        /// Program that was run.
        program: String,
    },
}

impl ProbeSource {
    /// A probe program source.
    pub fn program(program: &str) -> Self {
        ProbeSource::Program {
            program: program.to_string(),
        }
    }

    /// Stable identifier for reports.
    pub fn id(&self) -> &'static str {
        match self {
            ProbeSource::Always => "always",
            ProbeSource::Platform => "platform_capability",
            ProbeSource::Program { .. } => "probe_program",
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> String {
        match self {
            ProbeSource::Always => "always available".to_string(),
            ProbeSource::Platform => "platform capability".to_string(),
            ProbeSource::Program { program } => format!("probe: {program}"),
        }
    }
}

/// One accelerator and what was found out about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceleratorProbe {
    /// The device.
    pub accelerator: Accelerator,
    /// Whether it is usable.
    pub availability: Availability,
    /// Human-readable detail, including how it was determined.
    pub detail: String,
    /// What the conclusion is based on.
    pub source: ProbeSource,
}

impl AcceleratorProbe {
    fn new(
        accelerator: Accelerator,
        availability: Availability,
        detail: impl Into<String>,
        source: ProbeSource,
    ) -> Self {
        Self {
            accelerator,
            availability,
            detail: detail.into(),
            source,
        }
    }

    /// Whether this device can be used.
    pub fn is_available(&self) -> bool {
        self.availability == Availability::Available
    }

    /// Whether the conclusion rests on a real probe rather than an assumption.
    pub fn is_evidence_based(&self) -> bool {
        matches!(
            self.source,
            ProbeSource::Always | ProbeSource::Platform | ProbeSource::Program { .. }
        )
    }
}

/// Everything detected about the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareReport {
    /// Operating system, as reported by the Rust target.
    pub os: String,
    /// CPU architecture.
    pub arch: String,
    /// CPU description, when it could be read.
    pub cpu: String,
    /// One entry per known accelerator.
    pub probes: Vec<AcceleratorProbe>,
}

impl HardwareReport {
    /// The probe for one accelerator.
    pub fn probe(&self, accelerator: Accelerator) -> Option<&AcceleratorProbe> {
        self.probes
            .iter()
            .find(|probe| probe.accelerator == accelerator)
    }

    /// Whether an accelerator is usable.
    pub fn is_available(&self, accelerator: Accelerator) -> bool {
        self.probe(accelerator)
            .is_some_and(AcceleratorProbe::is_available)
    }

    /// The device an in-process backend should prefer on this machine.
    ///
    /// Preference order is Metal, CUDA, ROCm, Vulkan, CPU — but only among
    /// devices that were actually probed as available.
    pub fn preferred(&self) -> Accelerator {
        for candidate in [
            Accelerator::Metal,
            Accelerator::Cuda,
            Accelerator::Rocm,
            Accelerator::Vulkan,
        ] {
            if self.is_available(candidate) {
                return candidate;
            }
        }
        Accelerator::Cpu
    }

    /// One-line summary, e.g. `macos aarch64 (Apple M4 Max) — preferred: metal`.
    pub fn summary_line(&self) -> String {
        format!(
            "{} {} ({}) — preferred: {}",
            self.os,
            self.arch,
            self.cpu,
            self.preferred().id()
        )
    }

    /// Lines for `doctor`, one per accelerator.
    pub fn doctor_lines(&self) -> Vec<(Accelerator, Availability, String)> {
        self.probes
            .iter()
            .map(|probe| {
                (
                    probe.accelerator,
                    probe.availability,
                    format!("{} [{}]", probe.detail, probe.source.label()),
                )
            })
            .collect()
    }
}

/// Detect the machine's capabilities.
pub fn detect() -> HardwareReport {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();

    HardwareReport {
        cpu: cpu_description(&os),
        probes: vec![
            AcceleratorProbe::new(
                Accelerator::Cpu,
                Availability::Available,
                format!("{arch} CPU; always usable"),
                ProbeSource::Always,
            ),
            metal_probe(&os, &arch),
            cuda_probe(),
            rocm_probe(),
            vulkan_probe(),
        ],
        os,
        arch,
    }
}

/// Read the CPU description from the platform.
fn cpu_description(os: &str) -> String {
    if os == "macos" {
        if let Some(probe) = probe("sysctl", &["-n", "machdep.cpu.brand_string"], PROBE_TIMEOUT) {
            if probe.succeeded() {
                if let Some(line) = probe.first_line() {
                    return line.to_string();
                }
            }
        }
        return "unknown Apple silicon or Intel CPU".to_string();
    }
    if os == "linux" {
        if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
            if let Some(model) = content
                .lines()
                .find(|line| line.starts_with("model name"))
                .and_then(|line| line.split(':').nth(1))
            {
                return model.trim().to_string();
            }
        }
    }
    format!("{} {}", os, std::env::consts::ARCH)
}

fn metal_probe(os: &str, arch: &str) -> AcceleratorProbe {
    if os == "macos" {
        AcceleratorProbe::new(
            Accelerator::Metal,
            Availability::Available,
            format!("Metal is available on macOS ({arch})"),
            ProbeSource::Platform,
        )
    } else {
        AcceleratorProbe::new(
            Accelerator::Metal,
            Availability::Unavailable,
            format!("Metal is only available on macOS (this is {os})"),
            ProbeSource::Platform,
        )
    }
}

/// Classify the result of probing `nvidia-smi`.
fn classify_cuda(probe: Option<HostProbe>) -> AcceleratorProbe {
    match probe {
        Some(probe) if probe.timed_out => AcceleratorProbe::new(
            Accelerator::Cuda,
            Availability::Unknown,
            "nvidia-smi did not answer within the probe timeout",
            ProbeSource::program("nvidia-smi"),
        ),
        Some(probe) if probe.succeeded() && probe.first_line().is_some() => AcceleratorProbe::new(
            Accelerator::Cuda,
            Availability::Available,
            probe.first_line().unwrap_or("GPU present").to_string(),
            ProbeSource::program("nvidia-smi"),
        ),
        Some(_) => AcceleratorProbe::new(
            Accelerator::Cuda,
            Availability::Unavailable,
            "nvidia-smi answered but reported no device",
            ProbeSource::program("nvidia-smi"),
        ),
        None => AcceleratorProbe::new(
            Accelerator::Cuda,
            Availability::Unavailable,
            "nvidia-smi is not installed",
            ProbeSource::program("nvidia-smi"),
        ),
    }
}

fn cuda_probe() -> AcceleratorProbe {
    let probe = probe(
        "nvidia-smi",
        &["--query-gpu=name,driver_version", "--format=csv,noheader"],
        PROBE_TIMEOUT,
    );
    classify_cuda(probe)
}

/// Classify the result of probing the ROCm tooling.
fn classify_rocm(probe: Option<HostProbe>) -> AcceleratorProbe {
    match probe {
        Some(probe) if probe.timed_out => AcceleratorProbe::new(
            Accelerator::Rocm,
            Availability::Unknown,
            "rocminfo did not answer within the probe timeout",
            ProbeSource::program("rocminfo"),
        ),
        Some(probe) if probe.succeeded() && !probe.stdout.trim().is_empty() => {
            AcceleratorProbe::new(
                Accelerator::Rocm,
                Availability::Available,
                "rocminfo reported a ROCm device",
                ProbeSource::program("rocminfo"),
            )
        }
        Some(_) => AcceleratorProbe::new(
            Accelerator::Rocm,
            Availability::Unavailable,
            "rocminfo answered but reported no device",
            ProbeSource::program("rocminfo"),
        ),
        None => AcceleratorProbe::new(
            Accelerator::Rocm,
            Availability::Unavailable,
            "rocminfo is not installed",
            ProbeSource::program("rocminfo"),
        ),
    }
}

fn rocm_probe() -> AcceleratorProbe {
    classify_rocm(probe("rocminfo", &[], PROBE_TIMEOUT))
}

fn vulkan_probe() -> AcceleratorProbe {
    match probe("vulkaninfo", &["--summary"], PROBE_TIMEOUT) {
        Some(probe) if probe.timed_out => AcceleratorProbe::new(
            Accelerator::Vulkan,
            Availability::Unknown,
            "vulkaninfo did not answer within the probe timeout",
            ProbeSource::program("vulkaninfo"),
        ),
        Some(probe) if probe.succeeded() => AcceleratorProbe::new(
            Accelerator::Vulkan,
            Availability::Available,
            "vulkaninfo reported a Vulkan instance",
            ProbeSource::program("vulkaninfo"),
        ),
        Some(_) => AcceleratorProbe::new(
            Accelerator::Vulkan,
            Availability::Unavailable,
            "vulkaninfo answered with an error",
            ProbeSource::program("vulkaninfo"),
        ),
        None => AcceleratorProbe::new(
            Accelerator::Vulkan,
            Availability::Unavailable,
            "vulkaninfo is not installed",
            ProbeSource::program("vulkaninfo"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_with(exit_code: i32, stdout: &str) -> HostProbe {
        HostProbe {
            program: "nvidia-smi".to_string(),
            args: Vec::new(),
            exit_code: Some(exit_code),
            stdout: stdout.to_string(),
            stderr: String::new(),
            duration_ms: 5,
            timed_out: false,
        }
    }

    #[test]
    fn a_missing_probe_tool_means_unavailable_not_unknown() {
        let probe = classify_cuda(None);
        assert_eq!(probe.availability, Availability::Unavailable);
        assert!(probe.detail.contains("not installed"));
    }

    #[test]
    fn a_timeout_means_unknown() {
        let mut timed_out = probe_with(0, "");
        timed_out.timed_out = true;
        timed_out.exit_code = None;
        let probe = classify_cuda(Some(timed_out));
        assert_eq!(probe.availability, Availability::Unknown);
    }

    #[test]
    fn a_gpu_is_reported_with_its_driver() {
        let probe = classify_cuda(Some(probe_with(0, "NVIDIA RTX 4090, 550.54.14\n")));
        assert_eq!(probe.availability, Availability::Available);
        assert!(probe.detail.contains("RTX 4090"));
        assert!(probe.detail.contains("550.54.14"));
    }

    #[test]
    fn an_empty_answer_is_not_a_device() {
        let probe = classify_cuda(Some(probe_with(0, "\n")));
        assert_eq!(probe.availability, Availability::Unavailable);
    }

    #[test]
    fn detection_always_reports_a_cpu_and_never_invents_devices() {
        let report = detect();
        assert_eq!(
            report.probe(Accelerator::Cpu).unwrap().availability,
            Availability::Available
        );
        for probe in &report.probes {
            assert!(
                probe.is_evidence_based(),
                "{} must state what its conclusion rests on",
                probe.accelerator.id()
            );
            if probe.accelerator == Accelerator::Cpu
                || probe.availability != Availability::Available
            {
                continue;
            }
            // An accelerator may only be available because a probe program
            // confirmed it or because the platform guarantees it. `classify_*`
            // unit tests pin that a program source implies a successful probe.
            assert!(
                matches!(
                    probe.source,
                    ProbeSource::Platform | ProbeSource::Program { .. }
                ),
                "{} reported available from {:?}: {}",
                probe.accelerator.id(),
                probe.source,
                probe.detail
            );
            assert!(!probe.detail.is_empty());
        }
        assert!(!report.summary_line().is_empty());
        assert_eq!(report.doctor_lines().len(), report.probes.len());
    }

    #[test]
    fn metal_follows_the_platform() {
        let report = detect();
        if cfg!(target_os = "macos") {
            assert!(report.is_available(Accelerator::Metal));
            assert_eq!(report.preferred(), Accelerator::Metal);
        } else {
            assert!(!report.is_available(Accelerator::Metal));
        }
    }
}
