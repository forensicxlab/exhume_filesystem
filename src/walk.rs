//! Structured filesystem discovery. Local metadata failures leave an explicit
//! coverage gap while independent entries remain discoverable.
use crate::filesystem::{DirectoryCommon, File, FileCommon, FileIdentity, Filesystem};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalkStatus {
    Complete,
    CompletedWithIssues,
    Cancelled,
    Aborted,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalkStage {
    RecordRead,
    IdentityValidation,
    AttributeList,
    DirectoryRead,
    DirectoryIndex,
    Traversal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalkIssueCode {
    RecordReadFailed,
    AttributeListInvalid,
    StaleReference,
    InactiveRecord,
    ExtensionRecordReference,
    DirectoryReadFailed,
    InvalidIndexBlock,
    TruncatedIndexBlock,
    IndexBlockReadFailed,
    InvalidParentReference,
    InvalidIndexRoot,
    DirectoryCycle,
    DepthLimit,
    EntryLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalkAction {
    SkipEntry,
    SkipSubtree,
    SkipIndexBlock,
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalkIssue {
    pub path: String,
    pub record_id: Option<u64>,
    pub identity: Option<FileIdentity>,
    pub expected_generation: Option<u64>,
    pub stage: WalkStage,
    pub code: WalkIssueCode,
    pub action: WalkAction,
    pub index_block: Option<u64>,
    pub message: String,
}

impl WalkIssue {
    pub fn new(
        path: impl Into<String>,
        stage: WalkStage,
        code: WalkIssueCode,
        action: WalkAction,
        message: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            record_id: None,
            identity: None,
            expected_generation: None,
            stage,
            code,
            action,
            index_block: None,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalkReport {
    pub status: WalkStatus,
    pub files: u64,
    pub directories: u64,
    pub skipped_entries: u64,
    pub unreadable_subtrees: u64,
    pub skipped_index_blocks: u64,
    pub issues: u64,
}

impl Default for WalkReport {
    fn default() -> Self {
        Self {
            status: WalkStatus::Complete,
            files: 0,
            directories: 0,
            skipped_entries: 0,
            unreadable_subtrees: 0,
            skipped_index_blocks: 0,
            issues: 0,
        }
    }
}
impl WalkReport {
    pub fn discovered(&self) -> u64 {
        self.files + self.directories
    }
    pub fn record_issue(&mut self, issue: &WalkIssue) {
        self.issues += 1;
        if self.status == WalkStatus::Complete {
            self.status = WalkStatus::CompletedWithIssues;
        }
        match issue.action {
            WalkAction::SkipEntry => self.skipped_entries += 1,
            WalkAction::SkipSubtree => self.unreadable_subtrees += 1,
            WalkAction::SkipIndexBlock => self.skipped_index_blocks += 1,
            WalkAction::Stop => self.status = WalkStatus::Aborted,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WalkOptions {
    pub cancel_token: Option<Arc<AtomicBool>>,
    pub max_depth: usize,
    pub max_entries: u64,
}
impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            cancel_token: None,
            max_depth: 1024,
            max_entries: 2_000_000,
        }
    }
}
impl WalkOptions {
    pub fn is_cancelled(&self) -> bool {
        self.cancel_token
            .as_ref()
            .is_some_and(|token| token.load(Ordering::Relaxed))
    }
}

/// A streamed entry, progress update, or recoverable coverage gap.
#[allow(clippy::large_enum_variant)]
pub enum WalkEvent {
    File(File),
    Status(String),
    Issue(WalkIssue),
}

/// Consumer failures stop traversal; diagnostics must never be silently lost.
pub type WalkCallback<'a> = dyn FnMut(WalkEvent) -> Result<(), Box<dyn Error>> + 'a;
pub type WalkResult<T> = Result<T, WalkError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkErrorKind {
    Source,
    Callback,
}

/// Fatal traversal failure, including coverage observed before the failure.
#[derive(Debug)]
pub struct WalkError {
    pub kind: WalkErrorKind,
    pub report: WalkReport,
    pub path: String,
    source: Box<dyn Error>,
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "filesystem walk {:?} failure at {:?}: {}",
            self.kind, self.path, self.source
        )
    }
}
impl Error for WalkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// A filesystem namespace root; APFS supplies one per valid volume.
pub struct WalkRoot {
    pub identifier: u64,
    pub path: String,
}

/// Backend hooks report typed gaps through this context. It owns logging,
/// callback delivery, counters and cancellation for every filesystem.
pub struct WalkContext<'a> {
    options: WalkOptions,
    callback: &'a mut WalkCallback<'a>,
    report: WalkReport,
    path: String,
    record_id: Option<u64>,
    identity: Option<FileIdentity>,
    root: bool,
    attempted: u64,
}

impl WalkContext<'_> {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn is_root(&self) -> bool {
        self.root
    }
    pub fn is_cancelled(&mut self) -> bool {
        if self.options.is_cancelled() {
            self.report.status = WalkStatus::Cancelled;
            true
        } else {
            false
        }
    }
    pub fn restrict_limits(&mut self, depth: usize, entries: u64) {
        self.options.max_depth = self.options.max_depth.min(depth);
        self.options.max_entries = self.options.max_entries.min(entries);
    }
    pub fn source_error(&self, source: impl Into<Box<dyn Error>>) -> WalkError {
        self.failure(WalkErrorKind::Source, source.into())
    }
    fn failure(&self, kind: WalkErrorKind, source: Box<dyn Error>) -> WalkError {
        let mut report = self.report.clone();
        report.status = WalkStatus::Failed;
        WalkError {
            kind,
            report,
            path: self.path.clone(),
            source,
        }
    }
    fn deliver(&mut self, event: WalkEvent) -> WalkResult<()> {
        (self.callback)(event).map_err(|source| self.failure(WalkErrorKind::Callback, source))
    }
    pub fn status(&mut self, message: String) -> WalkResult<()> {
        self.deliver(WalkEvent::Status(message))
    }
    pub fn issue(&mut self, issue: WalkIssue) -> WalkResult<()> {
        self.report.record_issue(&issue);
        log::warn!(target: "exhume_filesystem::walk", "{:?}: {:?} ({:?}, record {:?}, block {:?}): {}",
            issue.path, issue.code, issue.action, issue.record_id, issue.index_block, issue.message);
        self.deliver(WalkEvent::Issue(issue))
    }
    pub fn read_failure(
        &mut self,
        stage: WalkStage,
        code: WalkIssueCode,
        action: WalkAction,
        error: impl std::fmt::Display,
    ) -> WalkResult<()> {
        let mut issue = WalkIssue::new(&self.path, stage, code, action, error.to_string());
        issue.record_id = self.record_id;
        issue.identity = self.identity;
        self.issue(issue)
    }
    fn location(&mut self, path: String, record_id: u64, root: bool) {
        self.path = path;
        self.record_id = Some(record_id);
        self.identity = None;
        self.root = root;
    }
    fn reserve_entry(&mut self) -> WalkResult<bool> {
        if self.is_cancelled() {
            return Ok(false);
        }
        if self.attempted >= self.options.max_entries {
            self.read_failure(
                WalkStage::Traversal,
                WalkIssueCode::EntryLimit,
                WalkAction::Stop,
                "filesystem walk entry limit reached",
            )?;
            return Ok(false);
        }
        self.attempted += 1;
        Ok(true)
    }
}

struct Frame<F: Filesystem + ?Sized> {
    record: F::FileType,
    entries: std::vec::IntoIter<F::DirectoryType>,
    path: String,
    identity: FileIdentity,
}

/// The single traversal engine. Only ancestor records and their directory
/// iterators remain live; regular files stream directly to the consumer.
pub(crate) fn run<F: Filesystem + ?Sized>(
    fs: &mut F,
    options: &WalkOptions,
    callback: &mut WalkCallback<'_>,
) -> WalkResult<WalkReport> {
    let mut context = WalkContext {
        options: options.clone(),
        callback,
        report: WalkReport::default(),
        path: fs.path_separator(),
        record_id: None,
        identity: None,
        root: true,
        attempted: 0,
    };
    let result = traverse(fs, &mut context);
    // Release backend scan caches on success, cancellation and every error path.
    fs.finish_walk();
    result.map(|()| context.report)
}

fn traverse<F: Filesystem + ?Sized>(fs: &mut F, context: &mut WalkContext<'_>) -> WalkResult<()> {
    if context.is_cancelled() {
        return Ok(());
    }
    let separator = fs.path_separator();
    let roots = fs.walk_roots(context)?;
    for root in roots {
        context.location(root.path, root.identifier, true);
        if !context.reserve_entry()? {
            return Ok(());
        }
        let Some(record) = fs.walk_root(root.identifier, context)? else {
            continue;
        };
        let mut stack: Vec<Frame<F>> = Vec::new();
        if let Some(frame) = enter(fs, record, &stack, context)? {
            stack.push(frame);
        }
        if matches!(
            context.report.status,
            WalkStatus::Aborted | WalkStatus::Cancelled
        ) {
            return Ok(());
        }
        while !stack.is_empty() {
            if context.is_cancelled() {
                return Ok(());
            }
            let next = {
                let Some(parent) = stack.last_mut() else {
                    break;
                };
                match parent.entries.next() {
                    Some(entry) if matches!(entry.name(), "." | "..") => continue,
                    Some(entry) => {
                        let path = if parent.path == separator {
                            format!("{separator}{}", entry.name())
                        } else {
                            format!("{}{separator}{}", parent.path, entry.name())
                        };
                        let identifier = fs.entry_identifier(&parent.record, &entry);
                        context.location(path, identifier, false);
                        if !context.reserve_entry()? {
                            return Ok(());
                        }
                        fs.walk_child(&parent.record, &entry, context)?
                    }
                    None => {
                        stack.pop();
                        continue;
                    }
                }
            };
            if let Some(record) = next
                && let Some(frame) = enter(fs, record, &stack, context)?
            {
                stack.push(frame);
            }
            if matches!(
                context.report.status,
                WalkStatus::Aborted | WalkStatus::Cancelled
            ) {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn enter<F: Filesystem + ?Sized>(
    fs: &mut F,
    record: F::FileType,
    stack: &[Frame<F>],
    context: &mut WalkContext<'_>,
) -> WalkResult<Option<Frame<F>>> {
    let identity = fs.file_identity(&record);
    context.identity = Some(identity);
    if record.is_dir() && stack.iter().any(|parent| parent.identity == identity) {
        context.read_failure(
            WalkStage::Traversal,
            WalkIssueCode::DirectoryCycle,
            WalkAction::SkipSubtree,
            "cyclic directory reference",
        )?;
        return Ok(None);
    }
    if record.is_dir() {
        context.report.directories += 1;
    } else {
        context.report.files += 1;
    }
    context.deliver(WalkEvent::File(fs.record_to_file(
        &record,
        fs.file_identifier(&record),
        &context.path,
    )))?;
    if context.is_cancelled() || !record.is_dir() {
        return Ok(None);
    }
    let entries = fs.walk_directory(&record, context)?;
    if context.is_cancelled() {
        return Ok(None);
    }
    if entries
        .iter()
        .any(|entry| !matches!(entry.name(), "." | ".."))
        && stack.len() >= context.options.max_depth
    {
        context.read_failure(
            WalkStage::Traversal,
            WalkIssueCode::DepthLimit,
            WalkAction::Stop,
            "filesystem walk depth limit reached",
        )?;
        return Ok(None);
    }
    Ok(Some(Frame {
        record,
        entries: entries.into_iter(),
        path: context.path.clone(),
        identity,
    }))
}
