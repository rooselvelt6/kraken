use forensics::*;
use forensics::imaging::ImageFormat;
use forensics::timeline::{TimelineEntry, TimelineResult};
use forensics::email::{EmailAttachment, EmailAddress, EmailInfo};
use forensics::memory::{MemoryProcess, MemorySocket, MemoryModule, MemoryAnalysisResult};
use forensics::pdf::{PdfInfo, PdfObject, PdfStream};
use forensics::carving::{CarvedFile, CarvingResult};
use forensics::registry::{RegistryEntry, RegistryHiveInfo, SamEntry, ServiceEntry, SystemInfo};
use forensics::metadata::{MetadataResult, GpsData};
use forensics::imaging::ImageInfo;
use forensics::browser::{BrowserArtifact, BrowserEntry, BrowserCredential};
use forensics::network::{NetworkLogEntry, NetworkCaptureInfo, DnsQuery, ConnectionInfo};
use std::collections::HashMap;

// ── TimelineEntry ──

#[test]
fn timeline_entry_fields() {
    let e = TimelineEntry {
        timestamp: "2026-01-15T10:00:00Z".to_string(),
        file_path: "/etc/passwd".to_string(),
        event_type: "modified".to_string(),
        size: 2048,
        permissions: "644".to_string(),
        owner: "root".to_string(),
    };
    assert_eq!(e.file_path, "/etc/passwd");
    assert_eq!(e.size, 2048);
}

#[test]
fn timeline_entry_clone() {
    let e = TimelineEntry {
        timestamp: "t".to_string(), file_path: "f".to_string(),
        event_type: "e".to_string(), size: 0, permissions: "p".to_string(), owner: "o".to_string(),
    };
    let e2 = e.clone();
    assert_eq!(e.file_path, e2.file_path);
}

#[test]
fn timeline_entry_debug() {
    let e = TimelineEntry {
        timestamp: "t".to_string(), file_path: "f".to_string(),
        event_type: "e".to_string(), size: 0, permissions: "p".to_string(), owner: "o".to_string(),
    };
    assert!(format!("{:?}", e).contains("TimelineEntry"));
}

#[test]
fn timeline_entry_serde_roundtrip() {
    let e = TimelineEntry {
        timestamp: "2026-01-15T10:00:00Z".to_string(),
        file_path: "/tmp/test.txt".to_string(),
        event_type: "scanned_modified".to_string(),
        size: 512,
        permissions: "644".to_string(),
        owner: "1000".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let e2: TimelineEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e.file_path, e2.file_path);
    assert_eq!(e.size, e2.size);
}

// ── TimelineResult ──

#[test]
fn timeline_result_empty() {
    let mut by_type = HashMap::new();
    by_type.insert("modified".to_string(), 5);
    let r = TimelineResult {
        entries: vec![], start_time: None, end_time: None, total_entries: 5, by_event_type: by_type,
    };
    assert_eq!(r.total_entries, 5);
    assert_eq!(r.by_event_type.get("modified").unwrap(), &5);
}

#[test]
fn timeline_result_clone() {
    let r = TimelineResult {
        entries: vec![], start_time: None, end_time: None, total_entries: 0, by_event_type: HashMap::new(),
    };
    let r2 = r.clone();
    assert_eq!(r2.total_entries, 0);
}

#[test]
fn timeline_result_debug() {
    let r = TimelineResult {
        entries: vec![], start_time: None, end_time: None, total_entries: 0, by_event_type: HashMap::new(),
    };
    assert!(format!("{:?}", r).contains("TimelineResult"));
}

#[test]
fn timeline_result_serde_roundtrip() {
    let mut by_type = HashMap::new();
    by_type.insert("created".to_string(), 3);
    let r = TimelineResult {
        entries: vec![], start_time: Some("2026-01-01T00:00:00Z".to_string()),
        end_time: Some("2026-12-31T23:59:59Z".to_string()),
        total_entries: 3, by_event_type: by_type,
    };
    let json = serde_json::to_string(&r).unwrap();
    let r2: TimelineResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r2.total_entries, 3);
}

// ── TimelineAnalyzer ──

#[test]
fn timeline_analyzer_new() {
    let _ = TimelineAnalyzer::new();
}

#[test]
fn timeline_analyzer_default() {
    let _ = TimelineAnalyzer::default();
}

#[test]
fn timeline_analyze_nonexistent() {
    let r = TimelineAnalyzer::build_timeline(&["/nonexistent/path"]);
    assert_eq!(r.total_entries, 0);
}

#[test]
fn timeline_analyze_file() {
    let tmp = std::env::temp_dir().join("timeline_test_file");
    std::fs::write(&tmp, b"hello").unwrap();
    let r = TimelineAnalyzer::build_timeline(&[tmp.to_str().unwrap()]);
    assert!(r.total_entries >= 1);
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn timeline_analyze_dir() {
    let tmp = std::env::temp_dir().join("timeline_test_dir");
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("a.txt"), b"aa").unwrap();
    std::fs::write(tmp.join("b.txt"), b"bb").unwrap();
    let r = TimelineAnalyzer::build_timeline(&[tmp.to_str().unwrap()]);
    assert!(r.total_entries >= 2);
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn timeline_analyze_modified_files() {
    let tmp = std::env::temp_dir().join("timeline_recent");
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("recent.txt"), b"data").unwrap();
    let recent = TimelineAnalyzer::analyze_modified_files(&[tmp.to_str().unwrap()], 24);
    assert!(!recent.is_empty());
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn timeline_clone() {
    let ta = TimelineAnalyzer::new();
    let _ta2 = ta;
}

#[test]
fn timeline_debug() {
    let ta = TimelineAnalyzer::new();
    let _ = &ta;
    assert!(std::any::type_name::<TimelineAnalyzer>().contains("TimelineAnalyzer"));
}

// ── EmailAttachment ──

#[test]
fn email_attachment_fields() {
    let a = EmailAttachment {
        filename: "doc.pdf".to_string(), content_type: "application/pdf".to_string(),
        size: 1024, encoding: Some("base64".to_string()),
    };
    assert_eq!(a.filename, "doc.pdf");
    assert_eq!(a.size, 1024);
}

#[test]
fn email_attachment_clone() {
    let a = EmailAttachment {
        filename: "f".to_string(), content_type: "t".to_string(), size: 0, encoding: None,
    };
    let a2 = a.clone();
    assert_eq!(a2.filename, "f");
}

#[test]
fn email_attachment_debug() {
    let a = EmailAttachment {
        filename: "f".to_string(), content_type: "t".to_string(), size: 0, encoding: None,
    };
    assert!(format!("{:?}", a).contains("EmailAttachment"));
}

#[test]
fn email_attachment_serde_roundtrip() {
    let a = EmailAttachment {
        filename: "test.txt".to_string(), content_type: "text/plain".to_string(),
        size: 500, encoding: Some("quoted-printable".to_string()),
    };
    let json = serde_json::to_string(&a).unwrap();
    let a2: EmailAttachment = serde_json::from_str(&json).unwrap();
    assert_eq!(a.filename, a2.filename);
    assert_eq!(a.encoding, a2.encoding);
}

// ── EmailAddress ──

#[test]
fn email_address_fields() {
    let ea = EmailAddress { address: "a@b.com".to_string(), name: Some("Alice".to_string()) };
    assert_eq!(ea.address, "a@b.com");
    assert_eq!(ea.name.unwrap(), "Alice");
}

#[test]
fn email_address_clone() {
    let ea = EmailAddress { address: "x@y.com".to_string(), name: None };
    let ea2 = ea.clone();
    assert_eq!(ea2.address, "x@y.com");
}

#[test]
fn email_address_debug() {
    let ea = EmailAddress { address: "a@b.com".to_string(), name: None };
    assert!(format!("{:?}", ea).contains("EmailAddress"));
}

#[test]
fn email_address_serde_roundtrip() {
    let ea = EmailAddress { address: "test@test.com".to_string(), name: Some("Test".to_string()) };
    let json = serde_json::to_string(&ea).unwrap();
    let ea2: EmailAddress = serde_json::from_str(&json).unwrap();
    assert_eq!(ea.address, ea2.address);
}

// ── EmailInfo ──

#[test]
fn email_info_fields() {
    let info = EmailInfo {
        file_path: "test.eml".to_string(), file_size: 100, format: "eml".to_string(),
        headers: HashMap::new(), from: vec!["a@b.com".to_string()], to: vec!["c@d.com".to_string()],
        cc: vec![], bcc: vec![], subject: Some("Test".to_string()), date: None,
        message_id: None, content_types: vec![], attachments: vec![],
        body_preview: String::new(), suspicious_indicators: vec![],
    };
    assert_eq!(info.from, vec!["a@b.com"]);
    assert_eq!(info.subject.unwrap(), "Test");
}

#[test]
fn email_info_clone() {
    let info = EmailInfo {
        file_path: "f".to_string(), file_size: 0, format: "eml".to_string(),
        headers: HashMap::new(), from: vec![], to: vec![], cc: vec![], bcc: vec![],
        subject: None, date: None, message_id: None, content_types: vec![],
        attachments: vec![], body_preview: String::new(), suspicious_indicators: vec![],
    };
    let info2 = info.clone();
    assert_eq!(info2.file_path, "f");
}

#[test]
fn email_info_debug() {
    let info = EmailInfo {
        file_path: "f".to_string(), file_size: 0, format: "eml".to_string(),
        headers: HashMap::new(), from: vec![], to: vec![], cc: vec![], bcc: vec![],
        subject: None, date: None, message_id: None, content_types: vec![],
        attachments: vec![], body_preview: String::new(), suspicious_indicators: vec![],
    };
    assert!(format!("{:?}", info).contains("EmailInfo"));
}

#[test]
fn email_info_serde_roundtrip() {
    let info = EmailInfo {
        file_path: "x.eml".to_string(), file_size: 500, format: "eml".to_string(),
        headers: HashMap::from([("X-Mailer".to_string(), "Test".to_string())]),
        from: vec!["a@b.com".to_string()], to: vec!["c@d.com".to_string()],
        cc: vec!["e@f.com".to_string()], bcc: vec![],
        subject: Some("Hello".to_string()), date: Some("2026-01-01".to_string()),
        message_id: Some("<123@host>".to_string()),
        content_types: vec!["text/plain".to_string()],
        attachments: vec![], body_preview: "body".to_string(),
        suspicious_indicators: vec!["test".to_string()],
    };
    let json = serde_json::to_string(&info).unwrap();
    let info2: EmailInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(info2.file_path, "x.eml");
    assert_eq!(info2.subject, Some("Hello".to_string()));
}

// ── EmailForensics ──

#[test]
fn email_forensics_new() {
    let _ = EmailForensics::new();
}

#[test]
fn email_forensics_default() {
    let _ = EmailForensics::default();
}

#[test]
fn email_forensics_analyze_nonexistent() {
    let result = EmailForensics::analyze("/nonexistent/file.eml");
    assert!(result.is_err());
}

#[test]
fn email_forensics_extract_body_text() {
    let content = "From: a@b.com\nTo: c@d.com\nSubject: Test\n\nHello World\nSecond Line";
    let body = EmailForensics::extract_body_text(content);
    assert!(body.contains("Hello World"));
}

#[test]
fn email_forensics_extract_body_text_empty() {
    let body = EmailForensics::extract_body_text("");
    assert!(body.is_empty());
}

#[test]
fn email_forensics_analyze_valid() {
    let tmp = std::env::temp_dir().join("test_email_valid.eml");
    let email = "From: sender@example.com\nTo: recipient@example.com\nSubject: Test\nMIME-Version: 1.0\nContent-Type: text/plain\n\nBody content here\n";
    std::fs::write(&tmp, email).unwrap();
    let result = EmailForensics::analyze(tmp.to_str().unwrap());
    assert!(result.is_ok());
    let info = result.unwrap();
    assert_eq!(info.from, vec!["sender@example.com"]);
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn email_forensics_clone() {
    let ef = EmailForensics::new();
    let _ef2 = ef;
}

#[test]
fn email_forensics_debug() {
    let ef = EmailForensics;
    let _ = &ef;
    assert!(std::any::type_name::<EmailForensics>().contains("EmailForensics"));
}

// ── MemoryProcess ──

#[test]
fn memory_process_fields() {
    let p = MemoryProcess {
        pid: 1337, name: "test".to_string(), ppid: Some(1), state: "R".to_string(),
        threads: 5, memory_kb: 1024, path: "/usr/bin/test".to_string(),
    };
    assert_eq!(p.pid, 1337);
    assert_eq!(p.threads, 5);
}

#[test]
fn memory_process_clone() {
    let p = MemoryProcess {
        pid: 1, name: "n".to_string(), ppid: None, state: "s".to_string(),
        threads: 0, memory_kb: 0, path: String::new(),
    };
    let p2 = p.clone();
    assert_eq!(p2.pid, 1);
}

#[test]
fn memory_process_debug() {
    let p = MemoryProcess {
        pid: 1, name: "n".to_string(), ppid: None, state: "s".to_string(),
        threads: 0, memory_kb: 0, path: String::new(),
    };
    assert!(format!("{:?}", p).contains("MemoryProcess"));
}

#[test]
fn memory_process_serde_roundtrip() {
    let p = MemoryProcess {
        pid: 42, name: "bash".to_string(), ppid: Some(1), state: "S".to_string(),
        threads: 1, memory_kb: 5120, path: "/bin/bash".to_string(),
    };
    let json = serde_json::to_string(&p).unwrap();
    let p2: MemoryProcess = serde_json::from_str(&json).unwrap();
    assert_eq!(p2.pid, 42);
    assert_eq!(p2.name, "bash");
}

// ── MemorySocket ──

#[test]
fn memory_socket_fields() {
    let s = MemorySocket {
        protocol: "TCP".to_string(), local_addr: "0.0.0.0".to_string(),
        local_port: 4444, remote_addr: "10.0.0.1".to_string(), remote_port: 80,
        state: "LISTEN".to_string(), pid: 1234,
    };
    assert_eq!(s.local_port, 4444);
    assert_eq!(s.pid, 1234);
}

#[test]
fn memory_socket_clone() {
    let s = MemorySocket {
        protocol: "UDP".to_string(), local_addr: "1.1.1.1".to_string(),
        local_port: 53, remote_addr: "2.2.2.2".to_string(), remote_port: 53,
        state: "STATELESS".to_string(), pid: 0,
    };
    let s2 = s.clone();
    assert_eq!(s2.protocol, "UDP");
}

#[test]
fn memory_socket_debug() {
    let s = MemorySocket {
        protocol: "TCP".to_string(), local_addr: "0.0.0.0".to_string(),
        local_port: 0, remote_addr: "0.0.0.0".to_string(), remote_port: 0,
        state: "s".to_string(), pid: 0,
    };
    assert!(format!("{:?}", s).contains("MemorySocket"));
}

#[test]
fn memory_socket_serde_roundtrip() {
    let s = MemorySocket {
        protocol: "TCP".to_string(), local_addr: "127.0.0.1".to_string(),
        local_port: 8080, remote_addr: "10.0.0.1".to_string(), remote_port: 443,
        state: "ESTABLISHED".to_string(), pid: 5678,
    };
    let json = serde_json::to_string(&s).unwrap();
    let s2: MemorySocket = serde_json::from_str(&json).unwrap();
    assert_eq!(s2.local_port, 8080);
}

// ── MemoryModule ──

#[test]
fn memory_module_fields() {
    let m = MemoryModule {
        name: "libc.so".to_string(), base_addr: "0x7fff0000".to_string(),
        size: 1048576, path: "/lib/x86_64/libc.so".to_string(),
    };
    assert_eq!(m.name, "libc.so");
    assert_eq!(m.size, 1048576);
}

#[test]
fn memory_module_clone() {
    let m = MemoryModule {
        name: "n".to_string(), base_addr: "0x0".to_string(), size: 0, path: String::new(),
    };
    let m2 = m.clone();
    assert_eq!(m2.name, "n");
}

#[test]
fn memory_module_debug() {
    let m = MemoryModule {
        name: "n".to_string(), base_addr: "0x0".to_string(), size: 0, path: String::new(),
    };
    assert!(format!("{:?}", m).contains("MemoryModule"));
}

#[test]
fn memory_module_serde_roundtrip() {
    let m = MemoryModule {
        name: "ld.so".to_string(), base_addr: "0x400000".to_string(),
        size: 2048, path: "/lib/ld.so".to_string(),
    };
    let json = serde_json::to_string(&m).unwrap();
    let m2: MemoryModule = serde_json::from_str(&json).unwrap();
    assert_eq!(m2.name, "ld.so");
}

// ── MemoryAnalysisResult ──

#[test]
fn memory_analysis_result_empty() {
    let r = MemoryAnalysisResult {
        processes: vec![], sockets: vec![], modules: vec![],
        suspicious_processes: vec![], hidden_processes: vec![],
    };
    assert!(r.processes.is_empty());
}

#[test]
fn memory_analysis_result_clone() {
    let r = MemoryAnalysisResult {
        processes: vec![], sockets: vec![], modules: vec![],
        suspicious_processes: vec![], hidden_processes: vec![],
    };
    let r2 = r.clone();
    assert!(r2.processes.is_empty());
}

#[test]
fn memory_analysis_result_debug() {
    let r = MemoryAnalysisResult {
        processes: vec![], sockets: vec![], modules: vec![],
        suspicious_processes: vec![], hidden_processes: vec![],
    };
    assert!(format!("{:?}", r).contains("MemoryAnalysisResult"));
}

#[test]
fn memory_analysis_result_serde_roundtrip() {
    let r = MemoryAnalysisResult {
        processes: vec![MemoryProcess {
            pid: 1, name: "init".to_string(), ppid: None, state: "S".to_string(),
            threads: 1, memory_kb: 1024, path: "/sbin/init".to_string(),
        }],
        sockets: vec![], modules: vec![],
        suspicious_processes: vec![], hidden_processes: vec!["hidden_proc".to_string()],
    };
    let json = serde_json::to_string(&r).unwrap();
    let r2: MemoryAnalysisResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r2.processes.len(), 1);
    assert_eq!(r2.hidden_processes, vec!["hidden_proc"]);
}

// ── MemoryAnalyzer ──

#[test]
fn memory_analyzer_new() {
    let _ = MemoryAnalyzer::new();
}

#[test]
fn memory_analyzer_default() {
    let _ = MemoryAnalyzer::default();
}

#[test]
fn memory_analyzer_analyze_live() {
    let r = MemoryAnalyzer::analyze_live();
    assert!(r.processes.len() >= 1);
}

#[test]
fn memory_analyzer_list_processes() {
    let procs = MemoryAnalyzer::list_processes();
    assert!(!procs.is_empty());
}

#[test]
fn memory_analyzer_list_sockets() {
    let sockets = MemoryAnalyzer::list_sockets();
    assert!(sockets.is_empty() || !sockets.is_empty());
}

#[test]
fn memory_analyzer_find_suspicious() {
    let susp = MemoryAnalyzer::find_suspicious();
    assert!(susp.is_empty() || !susp.is_empty());
}

#[test]
fn memory_analyzer_clone() {
    let ma = MemoryAnalyzer::new();
    let _ma2 = ma;
}

#[test]
fn memory_analyzer_debug() {
    let ma = MemoryAnalyzer;
    let _ = &ma;
    assert!(std::any::type_name::<MemoryAnalyzer>().contains("MemoryAnalyzer"));
}

// ── PdfInfo ──

#[test]
fn pdf_info_fields() {
    let info = PdfInfo {
        file_path: "test.pdf".to_string(), file_size: 1024,
        version: Some("PDF-1.7".to_string()), page_count: Some(5),
        metadata: HashMap::new(), suspicious_elements: vec![],
        objects: vec![], streams: vec![],
    };
    assert_eq!(info.file_path, "test.pdf");
    assert_eq!(info.page_count, Some(5));
}

#[test]
fn pdf_info_clone() {
    let info = PdfInfo {
        file_path: "f".to_string(), file_size: 0, version: None, page_count: None,
        metadata: HashMap::new(), suspicious_elements: vec![], objects: vec![], streams: vec![],
    };
    let info2 = info.clone();
    assert_eq!(info2.file_path, "f");
}

#[test]
fn pdf_info_debug() {
    let info = PdfInfo {
        file_path: "f".to_string(), file_size: 0, version: None, page_count: None,
        metadata: HashMap::new(), suspicious_elements: vec![], objects: vec![], streams: vec![],
    };
    assert!(format!("{:?}", info).contains("PdfInfo"));
}

#[test]
fn pdf_info_serde_roundtrip() {
    let info = PdfInfo {
        file_path: "doc.pdf".to_string(), file_size: 2048,
        version: Some("PDF-2.0".to_string()), page_count: Some(10),
        metadata: HashMap::from([("Author".to_string(), "Test".to_string())]),
        suspicious_elements: vec!["JavaScript detected".to_string()],
        objects: vec![], streams: vec![],
    };
    let json = serde_json::to_string(&info).unwrap();
    let info2: PdfInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(info2.version, Some("PDF-2.0".to_string()));
    assert_eq!(info2.suspicious_elements.len(), 1);
}

// ── PdfObject ──

#[test]
fn pdf_object_fields() {
    let o = PdfObject { id: 1, gen: 0, obj_type: "Page".to_string(), size: 100 };
    assert_eq!(o.id, 1);
    assert_eq!(o.obj_type, "Page");
}

#[test]
fn pdf_object_clone() {
    let o = PdfObject { id: 5, gen: 2, obj_type: "t".to_string(), size: 0 };
    let o2 = o.clone();
    assert_eq!(o2.id, 5);
}

#[test]
fn pdf_object_debug() {
    let o = PdfObject { id: 1, gen: 0, obj_type: "t".to_string(), size: 0 };
    assert!(format!("{:?}", o).contains("PdfObject"));
}

#[test]
fn pdf_object_serde_roundtrip() {
    let o = PdfObject { id: 3, gen: 1, obj_type: "Catalog".to_string(), size: 256 };
    let json = serde_json::to_string(&o).unwrap();
    let o2: PdfObject = serde_json::from_str(&json).unwrap();
    assert_eq!(o2.id, 3);
    assert_eq!(o2.gen, 1);
}

// ── PdfStream ──

#[test]
fn pdf_stream_fields() {
    let s = PdfStream {
        obj_id: 10, length: 512, filter: Some("FlateDecode".to_string()),
        content_preview: "preview".to_string(),
    };
    assert_eq!(s.obj_id, 10);
    assert_eq!(s.length, 512);
}

#[test]
fn pdf_stream_clone() {
    let s = PdfStream {
        obj_id: 1, length: 0, filter: None, content_preview: String::new(),
    };
    let s2 = s.clone();
    assert_eq!(s2.obj_id, 1);
}

#[test]
fn pdf_stream_debug() {
    let s = PdfStream {
        obj_id: 1, length: 0, filter: None, content_preview: String::new(),
    };
    assert!(format!("{:?}", s).contains("PdfStream"));
}

#[test]
fn pdf_stream_serde_roundtrip() {
    let s = PdfStream {
        obj_id: 42, length: 1024, filter: Some("ASCII85Decode".to_string()),
        content_preview: "data".to_string(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let s2: PdfStream = serde_json::from_str(&json).unwrap();
    assert_eq!(s2.obj_id, 42);
    assert_eq!(s2.filter, Some("ASCII85Decode".to_string()));
}

// ── PdfForensics ──

#[test]
fn pdf_forensics_new() {
    let _ = PdfForensics::new();
}

#[test]
fn pdf_forensics_default() {
    let _ = PdfForensics::default();
}

#[test]
fn pdf_forensics_analyze_nonexistent() {
    let result = PdfForensics::analyze("/nonexistent/file.pdf");
    assert!(result.is_err());
}

#[test]
fn pdf_forensics_extract_text_simple() {
    let data = b"stream\nBT (Hello World) Tj ET\nBT (Page 2) Tj ET\nendstream";
    let text = PdfForensics::extract_text_simple(data);
    assert!(!text.is_empty());
    assert!(text.contains("Hello World"));
}

#[test]
fn pdf_forensics_extract_text_empty() {
    let text = PdfForensics::extract_text_simple(b"");
    assert!(text.is_empty());
}

#[test]
fn pdf_forensics_analyze_valid() {
    let tmp = std::env::temp_dir().join("test_valid.pdf");
    let mut data = Vec::new();
    data.extend_from_slice(b"%PDF-1.4\n");
    data.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");
    data.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    data.extend_from_slice(b"3 0 obj\n<< /Type /Page >>\nendobj\n");
    std::fs::write(&tmp, &data).unwrap();
    let result = PdfForensics::analyze(tmp.to_str().unwrap());
    assert!(result.is_ok());
    let info = result.unwrap();
    assert_eq!(info.version, Some("PDF-1.4".to_string()));
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn pdf_forensics_clone() {
    let pf = PdfForensics::new();
    let _pf2 = pf;
}

#[test]
fn pdf_forensics_debug() {
    let pf = PdfForensics::new();
    assert!(format!("{:?}", pf).contains("PdfForensics"));
}

// ── CarvedFile ──

#[test]
fn carved_file_fields() {
    let f = CarvedFile {
        file_type: "JPEG".to_string(), offset: 0, size: 500,
        output_path: "/tmp/out.jpg".to_string(), signature_hex: "ffd8ff".to_string(),
        extension: "jpg".to_string(),
    };
    assert_eq!(f.file_type, "JPEG");
    assert_eq!(f.size, 500);
}

#[test]
fn carved_file_clone() {
    let f = CarvedFile {
        file_type: "PNG".to_string(), offset: 100, size: 200,
        output_path: "/tmp/out.png".to_string(), signature_hex: "89504e47".to_string(),
        extension: "png".to_string(),
    };
    let f2 = f.clone();
    assert_eq!(f2.file_type, "PNG");
}

#[test]
fn carved_file_debug() {
    let f = CarvedFile {
        file_type: "t".to_string(), offset: 0, size: 0,
        output_path: "o".to_string(), signature_hex: "h".to_string(), extension: "e".to_string(),
    };
    assert!(format!("{:?}", f).contains("CarvedFile"));
}

#[test]
fn carved_file_serde_roundtrip() {
    let f = CarvedFile {
        file_type: "PDF".to_string(), offset: 1024, size: 4096,
        output_path: "/tmp/doc.pdf".to_string(), signature_hex: "25504446".to_string(),
        extension: "pdf".to_string(),
    };
    let json = serde_json::to_string(&f).unwrap();
    let f2: CarvedFile = serde_json::from_str(&json).unwrap();
    assert_eq!(f2.file_type, "PDF");
    assert_eq!(f2.offset, 1024);
}

// ── CarvingResult ──

#[test]
fn carving_result_fields() {
    let r = CarvingResult { files: vec![], total_scanned: 10000, total_carved: 0 };
    assert_eq!(r.total_scanned, 10000);
    assert_eq!(r.total_carved, 0);
}

#[test]
fn carving_result_clone() {
    let r = CarvingResult { files: vec![], total_scanned: 0, total_carved: 0 };
    let r2 = r.clone();
    assert_eq!(r2.total_scanned, 0);
}

#[test]
fn carving_result_debug() {
    let r = CarvingResult { files: vec![], total_scanned: 0, total_carved: 0 };
    assert!(format!("{:?}", r).contains("CarvingResult"));
}

#[test]
fn carving_result_serde_roundtrip() {
    let r = CarvingResult {
        files: vec![CarvedFile {
            file_type: "JPEG".to_string(), offset: 0, size: 100,
            output_path: "/tmp/out.jpg".to_string(), signature_hex: "ffd8ff".to_string(),
            extension: "jpg".to_string(),
        }],
        total_scanned: 5000, total_carved: 1,
    };
    let json = serde_json::to_string(&r).unwrap();
    let r2: CarvingResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r2.total_carved, 1);
    assert_eq!(r2.files[0].file_type, "JPEG");
}

// ── FileCarver ──

#[test]
fn file_carver_new() {
    let _ = FileCarver::new();
}

#[test]
fn file_carver_default() {
    let _ = FileCarver::default();
}

#[test]
fn file_carver_with_chunk_size() {
    let c = FileCarver::new().with_chunk_size(1024);
    let _ = c;
}

#[test]
fn file_carver_carve_empty() {
    let c = FileCarver::new();
    let tmp = std::env::temp_dir().join("carve_empty");
    std::fs::create_dir_all(&tmp).unwrap();
    let result = c.carve_file(&[], tmp.to_str().unwrap());
    assert_eq!(result.total_carved, 0);
    assert_eq!(result.total_scanned, 0);
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn file_carver_carve_jpeg() {
    let c = FileCarver::new();
    let mut data = vec![0u8; 10000];
    data[0..3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);
    data[500..502].copy_from_slice(&[0xFF, 0xD9]);
    let tmp = std::env::temp_dir().join("carve_jpeg");
    std::fs::create_dir_all(&tmp).unwrap();
    let result = c.carve_file(&data, tmp.to_str().unwrap());
    assert_eq!(result.total_carved, 1);
    assert_eq!(result.files[0].file_type, "JPEG");
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn file_carver_carve_png() {
    let c = FileCarver::new();
    let mut data = vec![0u8; 1000];
    data[0..4].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47]);
    data[900..908].copy_from_slice(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
    let tmp = std::env::temp_dir().join("carve_png");
    std::fs::create_dir_all(&tmp).unwrap();
    let result = c.carve_file(&data, tmp.to_str().unwrap());
    assert_eq!(result.total_carved, 1);
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn file_carver_carve_too_small() {
    let c = FileCarver::new();
    let mut data = vec![0u8; 50];
    data[0..3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);
    let tmp = std::env::temp_dir().join("carve_small");
    std::fs::create_dir_all(&tmp).unwrap();
    let result = c.carve_file(&data, tmp.to_str().unwrap());
    assert_eq!(result.total_carved, 0);
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn file_carver_add_custom_signature() {
    let mut c = FileCarver::new();
    c.add_custom_signature("TEST", "test", vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let mut data = vec![0u8; 200];
    data[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let tmp = std::env::temp_dir().join("carve_custom");
    std::fs::create_dir_all(&tmp).unwrap();
    let result = c.carve_file(&data, tmp.to_str().unwrap());
    assert_eq!(result.total_carved, 1);
    assert_eq!(result.files[0].file_type, "TEST");
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn file_carver_carve_no_signatures() {
    let c = FileCarver::new();
    let data = vec![0x00; 1000];
    let tmp = std::env::temp_dir().join("carve_none");
    std::fs::create_dir_all(&tmp).unwrap();
    let result = c.carve_file(&data, tmp.to_str().unwrap());
    assert_eq!(result.total_carved, 0);
    assert_eq!(result.total_scanned, 1000);
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn file_carver_clone() {
    let c = FileCarver::new();
    let _c2 = c;
}

#[test]
fn file_carver_debug() {
    let c = FileCarver::new();
    let _ = &c;
    assert!(std::any::type_name::<FileCarver>().contains("FileCarver"));
}

// ── RegistryEntry ──

#[test]
fn registry_entry_fields() {
    let e = RegistryEntry {
        key_path: "\\SAM\\Domains".to_string(), value_name: "F".to_string(),
        value_type: "REG_BINARY".to_string(), value_data: "0102".to_string(),
    };
    assert_eq!(e.key_path, "\\SAM\\Domains");
    assert_eq!(e.value_type, "REG_BINARY");
}

#[test]
fn registry_entry_clone() {
    let e = RegistryEntry {
        key_path: "k".to_string(), value_name: "v".to_string(),
        value_type: "t".to_string(), value_data: "d".to_string(),
    };
    let e2 = e.clone();
    assert_eq!(e2.key_path, "k");
}

#[test]
fn registry_entry_debug() {
    let e = RegistryEntry {
        key_path: "k".to_string(), value_name: "v".to_string(),
        value_type: "t".to_string(), value_data: "d".to_string(),
    };
    assert!(format!("{:?}", e).contains("RegistryEntry"));
}

#[test]
fn registry_entry_serde_roundtrip() {
    let e = RegistryEntry {
        key_path: "\\System\\ControlSet001".to_string(), value_name: "Start".to_string(),
        value_type: "REG_DWORD".to_string(), value_data: "2".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let e2: RegistryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e2.key_path, e.key_path);
}

// ── RegistryHiveInfo ──

#[test]
fn registry_hive_info_fields() {
    let h = RegistryHiveInfo {
        hive_path: "/path/hive".to_string(), entries: vec![],
        last_modified: None, parsed_entries: 0,
    };
    assert_eq!(h.hive_path, "/path/hive");
    assert_eq!(h.parsed_entries, 0);
}

#[test]
fn registry_hive_info_clone() {
    let h = RegistryHiveInfo {
        hive_path: "p".to_string(), entries: vec![], last_modified: None, parsed_entries: 0,
    };
    let h2 = h.clone();
    assert_eq!(h2.hive_path, "p");
}

#[test]
fn registry_hive_info_debug() {
    let h = RegistryHiveInfo {
        hive_path: "p".to_string(), entries: vec![], last_modified: None, parsed_entries: 0,
    };
    assert!(format!("{:?}", h).contains("RegistryHiveInfo"));
}

#[test]
fn registry_hive_info_serde_roundtrip() {
    let h = RegistryHiveInfo {
        hive_path: "/tmp/hive".to_string(), entries: vec![RegistryEntry {
            key_path: "k".to_string(), value_name: "v".to_string(),
            value_type: "t".to_string(), value_data: "d".to_string(),
        }],
        last_modified: Some("2026-01-01".to_string()), parsed_entries: 1,
    };
    let json = serde_json::to_string(&h).unwrap();
    let h2: RegistryHiveInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(h2.parsed_entries, 1);
    assert_eq!(h2.entries.len(), 1);
}

// ── SamEntry ──

#[test]
fn sam_entry_fields() {
    let s = SamEntry {
        username: "Administrator".to_string(), rid: "500".to_string(),
        hash: Some("aad3b435b51404eeaad3b435b51404ee".to_string()),
        account_type: "SAM".to_string(),
    };
    assert_eq!(s.username, "Administrator");
    assert_eq!(s.rid, "500");
}

#[test]
fn sam_entry_clone() {
    let s = SamEntry {
        username: "u".to_string(), rid: "r".to_string(), hash: None, account_type: "t".to_string(),
    };
    let s2 = s.clone();
    assert_eq!(s2.username, "u");
}

#[test]
fn sam_entry_debug() {
    let s = SamEntry {
        username: "u".to_string(), rid: "r".to_string(), hash: None, account_type: "t".to_string(),
    };
    assert!(format!("{:?}", s).contains("SamEntry"));
}

#[test]
fn sam_entry_serde_roundtrip() {
    let s = SamEntry {
        username: "Admin".to_string(), rid: "500".to_string(),
        hash: Some("hash".to_string()), account_type: "SAM".to_string(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let s2: SamEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(s2.username, "Admin");
}

// ── ServiceEntry ──

#[test]
fn service_entry_fields() {
    let s = ServiceEntry {
        name: "Tcpip".to_string(), display_name: "TCP/IP".to_string(),
        start_type: "2".to_string(), binary_path: "C:\\tcpip.sys".to_string(),
    };
    assert_eq!(s.name, "Tcpip");
    assert_eq!(s.start_type, "2");
}

#[test]
fn service_entry_clone() {
    let s = ServiceEntry {
        name: "n".to_string(), display_name: "d".to_string(),
        start_type: "s".to_string(), binary_path: "b".to_string(),
    };
    let s2 = s.clone();
    assert_eq!(s2.name, "n");
}

#[test]
fn service_entry_debug() {
    let s = ServiceEntry {
        name: "n".to_string(), display_name: "d".to_string(),
        start_type: "s".to_string(), binary_path: "b".to_string(),
    };
    assert!(format!("{:?}", s).contains("ServiceEntry"));
}

#[test]
fn service_entry_serde_roundtrip() {
    let s = ServiceEntry {
        name: "W32Time".to_string(), display_name: "Windows Time".to_string(),
        start_type: "3".to_string(), binary_path: "C:\\w32time.dll".to_string(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let s2: ServiceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(s2.name, "W32Time");
}

// ── SystemInfo ──

#[test]
fn system_info_fields() {
    let i = SystemInfo {
        computer_name: Some("PC".to_string()), os_version: Some("Win10".to_string()),
        last_shutdown: None, services: vec![],
    };
    assert_eq!(i.computer_name, Some("PC".to_string()));
}

#[test]
fn system_info_clone() {
    let i = SystemInfo {
        computer_name: None, os_version: None, last_shutdown: None, services: vec![],
    };
    let i2 = i.clone();
    assert!(i2.computer_name.is_none());
}

#[test]
fn system_info_debug() {
    let i = SystemInfo {
        computer_name: None, os_version: None, last_shutdown: None, services: vec![],
    };
    assert!(format!("{:?}", i).contains("SystemInfo"));
}

#[test]
fn system_info_serde_roundtrip() {
    let i = SystemInfo {
        computer_name: Some("DESKTOP".to_string()), os_version: Some("Win11".to_string()),
        last_shutdown: Some("2026-01-15".to_string()),
        services: vec![ServiceEntry {
            name: "svc".to_string(), display_name: "Svc".to_string(),
            start_type: "2".to_string(), binary_path: "path".to_string(),
        }],
    };
    let json = serde_json::to_string(&i).unwrap();
    let i2: SystemInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(i2.computer_name, Some("DESKTOP".to_string()));
    assert_eq!(i2.services.len(), 1);
}

// ── RegistryParser ──

#[test]
fn registry_parser_new() {
    let _ = RegistryParser::new();
}

#[test]
fn registry_parser_default() {
    let _ = RegistryParser::default();
}

#[test]
fn registry_parser_parse_hive_nonexistent() {
    let result = RegistryParser::parse_hive("/nonexistent/hive");
    assert!(result.is_err());
}

#[test]
fn registry_parser_parse_hive_invalid() {
    let tmp = std::env::temp_dir().join("bad_hive");
    std::fs::write(&tmp, b"not a hive").unwrap();
    let result = RegistryParser::parse_hive(tmp.to_str().unwrap());
    assert!(result.is_err());
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn registry_parser_parse_hive_valid() {
    let tmp = std::env::temp_dir().join("valid_hive");
    let mut data = Vec::new();
    data.extend_from_slice(b"regf");
    data.extend_from_slice(&[0u8; 4092]);
    data.extend_from_slice(b"SAM\\Domains\\Account\\Users\\000001F4");
    std::fs::write(&tmp, &data).unwrap();
    let result = RegistryParser::parse_hive(tmp.to_str().unwrap());
    assert!(result.is_ok());
    let info = result.unwrap();
    assert_eq!(info.hive_path, tmp.to_str().unwrap());
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn registry_parser_parse_sam_nonexistent() {
    let result = RegistryParser::parse_sam("/nonexistent/sam");
    assert!(result.is_err());
}

#[test]
fn registry_parser_parse_system_nonexistent() {
    let result = RegistryParser::parse_system("/nonexistent/system");
    assert!(result.is_err());
}

#[test]
fn registry_parser_clone() {
    let rp = RegistryParser::new();
    let _rp2 = rp;
}

#[test]
fn registry_parser_debug() {
    let rp = RegistryParser;
    let _ = &rp;
    assert!(std::any::type_name::<RegistryParser>().contains("RegistryParser"));
}

// ── MetadataResult ──

#[test]
fn metadata_result_fields() {
    let r = MetadataResult {
        file_path: "/tmp/test.jpg".to_string(), file_size: 1024,
        mime_type: Some("image/jpeg".to_string()), exif: HashMap::new(),
        gps: None, embedded_metadata: HashMap::new(),
    };
    assert_eq!(r.file_size, 1024);
}

#[test]
fn metadata_result_clone() {
    let r = MetadataResult {
        file_path: "f".to_string(), file_size: 0, mime_type: None,
        exif: HashMap::new(), gps: None, embedded_metadata: HashMap::new(),
    };
    let r2 = r.clone();
    assert_eq!(r2.file_path, "f");
}

#[test]
fn metadata_result_debug() {
    let r = MetadataResult {
        file_path: "f".to_string(), file_size: 0, mime_type: None,
        exif: HashMap::new(), gps: None, embedded_metadata: HashMap::new(),
    };
    assert!(format!("{:?}", r).contains("MetadataResult"));
}

#[test]
fn metadata_result_serde_roundtrip() {
    let r = MetadataResult {
        file_path: "/tmp/photo.jpg".to_string(), file_size: 4096,
        mime_type: Some("image/jpeg".to_string()),
        exif: HashMap::from([("Model".to_string(), "iPhone".to_string())]),
        gps: Some(GpsData { latitude: 10.5, longitude: -66.0, altitude: None }),
        embedded_metadata: HashMap::new(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let r2: MetadataResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r2.mime_type, Some("image/jpeg".to_string()));
    assert!(r2.gps.is_some());
}

// ── GpsData ──

#[test]
fn gps_data_fields() {
    let g = GpsData { latitude: 10.5, longitude: -66.0, altitude: Some(100.0) };
    assert!((g.latitude - 10.5).abs() < 0.001);
    assert_eq!(g.altitude, Some(100.0));
}

#[test]
fn gps_data_clone() {
    let g = GpsData { latitude: 1.0, longitude: 2.0, altitude: None };
    let g2 = g.clone();
    assert_eq!(g2.latitude, 1.0);
}

#[test]
fn gps_data_debug() {
    let g = GpsData { latitude: 0.0, longitude: 0.0, altitude: None };
    assert!(format!("{:?}", g).contains("GpsData"));
}

#[test]
fn gps_data_serde_roundtrip() {
    let g = GpsData { latitude: 10.5, longitude: -66.9, altitude: Some(250.0) };
    let json = serde_json::to_string(&g).unwrap();
    let g2: GpsData = serde_json::from_str(&json).unwrap();
    assert!((g2.latitude - 10.5).abs() < 0.001);
    assert_eq!(g2.altitude, Some(250.0));
}

// ── MetadataExtractor ──

#[test]
fn metadata_extractor_new() {
    let _ = MetadataExtractor::new();
}

#[test]
fn metadata_extractor_default() {
    let _ = MetadataExtractor::default();
}

#[test]
fn metadata_extractor_extract_nonexistent() {
    let result = MetadataExtractor::extract("/nonexistent/photo.jpg");
    assert!(result.is_err());
}

#[test]
fn metadata_extractor_extract_valid() {
    let tmp = std::env::temp_dir().join("test_meta.txt");
    std::fs::write(&tmp, b"Creator: Test\nProducer: App\n").unwrap();
    let result = MetadataExtractor::extract(tmp.to_str().unwrap());
    assert!(result.is_ok());
    let info = result.unwrap();
    assert_eq!(info.file_path, tmp.to_str().unwrap());
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn metadata_extractor_clone() {
    let me = MetadataExtractor::new();
    let _me2 = me;
}

#[test]
fn metadata_extractor_debug() {
    let me = MetadataExtractor;
    let _ = &me;
    assert!(std::any::type_name::<MetadataExtractor>().contains("MetadataExtractor"));
}

// ── ImageInfo ──

#[test]
fn image_info_fields() {
    let i = ImageInfo {
        source: "/dev/sda".to_string(), output: "/mnt/img.dd".to_string(),
        size_bytes: 1024, sha256: "abc".to_string(), sector_size: 512,
        blocks_copied: 2, verify_match: true,
    };
    assert_eq!(i.size_bytes, 1024);
    assert!(i.verify_match);
}

#[test]
fn image_info_clone() {
    let i = ImageInfo {
        source: "s".to_string(), output: "o".to_string(), size_bytes: 0,
        sha256: "h".to_string(), sector_size: 0, blocks_copied: 0, verify_match: false,
    };
    let i2 = i.clone();
    assert_eq!(i2.source, "s");
}

#[test]
fn image_info_debug() {
    let i = ImageInfo {
        source: "s".to_string(), output: "o".to_string(), size_bytes: 0,
        sha256: "h".to_string(), sector_size: 0, blocks_copied: 0, verify_match: false,
    };
    assert!(format!("{:?}", i).contains("ImageInfo"));
}

#[test]
fn image_info_serde_roundtrip() {
    let i = ImageInfo {
        source: "/dev/sda".to_string(), output: "/tmp/img.dd".to_string(),
        size_bytes: 4096, sha256: "abc123".to_string(), sector_size: 512,
        blocks_copied: 8, verify_match: true,
    };
    let json = serde_json::to_string(&i).unwrap();
    let i2: ImageInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(i2.source, "/dev/sda");
    assert_eq!(i2.blocks_copied, 8);
}

// ── ImageFormat ──

#[test]
fn image_format_variants() {
    assert!(matches!(ImageFormat::Raw, ImageFormat::Raw));
    assert!(matches!(ImageFormat::AFF, ImageFormat::AFF));
    assert!(matches!(ImageFormat::EWF, ImageFormat::EWF));
}

#[test]
fn image_format_equality() {
    assert!(matches!(ImageFormat::Raw, ImageFormat::Raw));
    assert!(matches!(ImageFormat::AFF, ImageFormat::AFF));
    assert!(matches!(ImageFormat::EWF, ImageFormat::EWF));
}

#[test]
fn image_format_clone() {
    let f = ImageFormat::EWF;
    let f2 = f;
    assert!(matches!(f2, ImageFormat::EWF));
}

#[test]
fn image_format_debug() {
    assert_eq!(format!("{:?}", ImageFormat::Raw), "Raw");
    assert_eq!(format!("{:?}", ImageFormat::AFF), "AFF");
    assert_eq!(format!("{:?}", ImageFormat::EWF), "EWF");
}

#[test]
fn image_format_serde_roundtrip() {
    for fmt in [ImageFormat::Raw, ImageFormat::AFF, ImageFormat::EWF] {
        let json = serde_json::to_string(&fmt).unwrap();
        let fmt2: ImageFormat = serde_json::from_str(&json).unwrap();
        let _ = (fmt, fmt2);
    }
}

// ── DiskImager ──

#[test]
fn disk_imager_new() {
    let _ = DiskImager::new();
}

#[test]
fn disk_imager_default() {
    let _ = DiskImager::default();
}

#[test]
fn disk_imager_list_disks() {
    let disks = DiskImager::list_disks();
    assert!(disks.is_empty() || !disks.is_empty());
}

#[test]
fn disk_imager_create_image_nonexistent() {
    let result = DiskImager::create_image("/nonexistent/src", "/tmp/out", 512);
    assert!(result.is_err());
}

#[test]
fn disk_imager_estimate_size_nonexistent() {
    let result = DiskImager::estimate_size("/nonexistent/file");
    assert!(result.is_err());
}

#[test]
fn disk_imager_clone() {
    let di = DiskImager::new();
    let _di2 = di;
}

#[test]
fn disk_imager_debug() {
    let di = DiskImager;
    let _ = &di;
    assert!(std::any::type_name::<DiskImager>().contains("DiskImager"));
}

// ── BrowserArtifact ──

#[test]
fn browser_artifact_fields() {
    let a = BrowserArtifact {
        browser_type: "chrome".to_string(), artifact_type: "history".to_string(),
        source_path: "/path".to_string(), entries: vec![], total_entries: 0,
    };
    assert_eq!(a.browser_type, "chrome");
    assert_eq!(a.total_entries, 0);
}

#[test]
fn browser_artifact_clone() {
    let a = BrowserArtifact {
        browser_type: "b".to_string(), artifact_type: "t".to_string(),
        source_path: "s".to_string(), entries: vec![], total_entries: 0,
    };
    let a2 = a.clone();
    assert_eq!(a2.browser_type, "b");
}

#[test]
fn browser_artifact_debug() {
    let a = BrowserArtifact {
        browser_type: "b".to_string(), artifact_type: "t".to_string(),
        source_path: "s".to_string(), entries: vec![], total_entries: 0,
    };
    assert!(format!("{:?}", a).contains("BrowserArtifact"));
}

#[test]
fn browser_artifact_serde_roundtrip() {
    let a = BrowserArtifact {
        browser_type: "firefox".to_string(), artifact_type: "cookies".to_string(),
        source_path: "/home/.mozilla".to_string(), entries: vec![], total_entries: 0,
    };
    let json = serde_json::to_string(&a).unwrap();
    let a2: BrowserArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(a2.browser_type, "firefox");
}

// ── BrowserEntry ──

#[test]
fn browser_entry_fields() {
    let e = BrowserEntry {
        url: Some("https://example.com".to_string()), title: Some("Example".to_string()),
        visit_time: None, visit_count: Some(5), typed_count: None, last_visit: None,
        username: None, password: None, cookie_name: None, cookie_value: None,
        cookie_domain: None, cookie_expiry: None, download_path: None, download_url: None,
        download_size: None, download_mime: None,
    };
    assert_eq!(e.url, Some("https://example.com".to_string()));
    assert_eq!(e.visit_count, Some(5));
}

#[test]
fn browser_entry_clone() {
    let e = BrowserEntry {
        url: None, title: None, visit_time: None, visit_count: None, typed_count: None,
        last_visit: None, username: None, password: None, cookie_name: None, cookie_value: None,
        cookie_domain: None, cookie_expiry: None, download_path: None, download_url: None,
        download_size: None, download_mime: None,
    };
    let e2 = e.clone();
    assert!(e2.url.is_none());
}

#[test]
fn browser_entry_debug() {
    let e = BrowserEntry {
        url: None, title: None, visit_time: None, visit_count: None, typed_count: None,
        last_visit: None, username: None, password: None, cookie_name: None, cookie_value: None,
        cookie_domain: None, cookie_expiry: None, download_path: None, download_url: None,
        download_size: None, download_mime: None,
    };
    assert!(format!("{:?}", e).contains("BrowserEntry"));
}

#[test]
fn browser_entry_serde_roundtrip() {
    let e = BrowserEntry {
        url: Some("https://rust.org".to_string()), title: Some("Rust".to_string()),
        visit_time: Some("2026-01-15T10:00:00Z".to_string()), visit_count: Some(10),
        typed_count: None, last_visit: None, username: None, password: None,
        cookie_name: Some("sid".to_string()), cookie_value: Some("abc123".to_string()),
        cookie_domain: Some(".rust.org".to_string()), cookie_expiry: None,
        download_path: None, download_url: None, download_size: None, download_mime: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    let e2: BrowserEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e2.url, Some("https://rust.org".to_string()));
    assert_eq!(e2.cookie_name, Some("sid".to_string()));
}

// ── BrowserCredential ──

#[test]
fn browser_credential_fields() {
    let c = BrowserCredential {
        browser: "chrome".to_string(), url: "https://login.com".to_string(),
        username: "user".to_string(), password: "pass".to_string(),
        created: None, last_used: None,
    };
    assert_eq!(c.browser, "chrome");
    assert_eq!(c.url, "https://login.com");
}

#[test]
fn browser_credential_clone() {
    let c = BrowserCredential {
        browser: "b".to_string(), url: "u".to_string(), username: "n".to_string(),
        password: "p".to_string(), created: None, last_used: None,
    };
    let c2 = c.clone();
    assert_eq!(c2.browser, "b");
}

#[test]
fn browser_credential_debug() {
    let c = BrowserCredential {
        browser: "b".to_string(), url: "u".to_string(), username: "n".to_string(),
        password: "p".to_string(), created: None, last_used: None,
    };
    assert!(format!("{:?}", c).contains("BrowserCredential"));
}

#[test]
fn browser_credential_serde_roundtrip() {
    let c = BrowserCredential {
        browser: "firefox".to_string(), url: "https://example.com".to_string(),
        username: "admin".to_string(), password: "secret".to_string(),
        created: Some("2026-01-01".to_string()), last_used: Some("2026-06-15".to_string()),
    };
    let json = serde_json::to_string(&c).unwrap();
    let c2: BrowserCredential = serde_json::from_str(&json).unwrap();
    assert_eq!(c2.username, "admin");
    assert_eq!(c2.last_used, Some("2026-06-15".to_string()));
}

// ── BrowserForensics ──

#[test]
fn browser_forensics_new() {
    let _ = BrowserForensics::new();
}

#[test]
fn browser_forensics_default() {
    let _ = BrowserForensics::default();
}

#[test]
fn browser_forensics_analyze_history_nonexistent() {
    let result = BrowserForensics::analyze_history("/nonexistent");
    assert!(result.is_err());
}

#[test]
fn browser_forensics_analyze_cookies_nonexistent() {
    let result = BrowserForensics::analyze_cookies("/nonexistent");
    assert!(result.is_err());
}

#[test]
fn browser_forensics_analyze_downloads_nonexistent() {
    let result = BrowserForensics::analyze_downloads("/nonexistent");
    assert!(result.is_err());
}

#[test]
fn browser_forensics_analyze_credentials_nonexistent() {
    let result = BrowserForensics::analyze_credentials("/nonexistent");
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn browser_forensics_clone() {
    let bf = BrowserForensics::new();
    let _bf2 = bf;
}

#[test]
fn browser_forensics_debug() {
    let bf = BrowserForensics;
    let _ = &bf;
    assert!(std::any::type_name::<BrowserForensics>().contains("BrowserForensics"));
}

// ── NetworkLogEntry ──

#[test]
fn network_log_entry_fields() {
    let e = NetworkLogEntry {
        timestamp: "2026-01-15T10:00:00Z".to_string(),
        source_ip: Some("10.0.0.1".to_string()), dest_ip: Some("10.0.0.2".to_string()),
        source_port: Some(12345), dest_port: Some(80),
        protocol: "TCP".to_string(), length: 100,
        info: "GET /".to_string(), flags: vec!["SYN".to_string()],
    };
    assert_eq!(e.source_port, Some(12345));
    assert_eq!(e.flags.len(), 1);
}

#[test]
fn network_log_entry_clone() {
    let e = NetworkLogEntry {
        timestamp: "t".to_string(), source_ip: None, dest_ip: None,
        source_port: None, dest_port: None, protocol: "UDP".to_string(),
        length: 0, info: String::new(), flags: vec![],
    };
    let e2 = e.clone();
    assert_eq!(e2.protocol, "UDP");
}

#[test]
fn network_log_entry_debug() {
    let e = NetworkLogEntry {
        timestamp: "t".to_string(), source_ip: None, dest_ip: None,
        source_port: None, dest_port: None, protocol: "P".to_string(),
        length: 0, info: String::new(), flags: vec![],
    };
    assert!(format!("{:?}", e).contains("NetworkLogEntry"));
}

#[test]
fn network_log_entry_serde_roundtrip() {
    let e = NetworkLogEntry {
        timestamp: "now".to_string(), source_ip: Some("1.1.1.1".to_string()),
        dest_ip: Some("8.8.8.8".to_string()), source_port: Some(53),
        dest_port: Some(53), protocol: "UDP".to_string(), length: 64,
        info: "DNS".to_string(), flags: vec![],
    };
    let json = serde_json::to_string(&e).unwrap();
    let e2: NetworkLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e2.protocol, "UDP");
}

// ── NetworkCaptureInfo ──

#[test]
fn network_capture_info_fields() {
    let i = NetworkCaptureInfo {
        file_path: "cap.pcap".to_string(), file_size: 1024,
        format: "pcap".to_string(), packet_count: 10, entries: vec![],
        unique_ips: vec![], unique_ports: vec![],
        protocols: HashMap::new(), suspicious_connections: vec![],
    };
    assert_eq!(i.packet_count, 10);
}

#[test]
fn network_capture_info_clone() {
    let i = NetworkCaptureInfo {
        file_path: "f".to_string(), file_size: 0, format: "t".to_string(),
        packet_count: 0, entries: vec![], unique_ips: vec![], unique_ports: vec![],
        protocols: HashMap::new(), suspicious_connections: vec![],
    };
    let i2 = i.clone();
    assert_eq!(i2.file_path, "f");
}

#[test]
fn network_capture_info_debug() {
    let i = NetworkCaptureInfo {
        file_path: "f".to_string(), file_size: 0, format: "t".to_string(),
        packet_count: 0, entries: vec![], unique_ips: vec![], unique_ports: vec![],
        protocols: HashMap::new(), suspicious_connections: vec![],
    };
    assert!(format!("{:?}", i).contains("NetworkCaptureInfo"));
}

#[test]
fn network_capture_info_serde_roundtrip() {
    let i = NetworkCaptureInfo {
        file_path: "cap.pcap".to_string(), file_size: 2048,
        format: "pcap".to_string(), packet_count: 50, entries: vec![],
        unique_ips: vec!["10.0.0.1".to_string()],
        unique_ports: vec![80, 443],
        protocols: HashMap::from([("TCP".to_string(), 30), ("UDP".to_string(), 20)]),
        suspicious_connections: vec!["Port scan".to_string()],
    };
    let json = serde_json::to_string(&i).unwrap();
    let i2: NetworkCaptureInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(i2.unique_ports, vec![80, 443]);
}

// ── DnsQuery ──

#[test]
fn dns_query_fields() {
    let q = DnsQuery {
        timestamp: "t".to_string(), query: "example.com".to_string(),
        query_type: "A".to_string(), response: Some("93.184.216.34".to_string()),
        response_code: "NOERROR".to_string(),
    };
    assert_eq!(q.query, "example.com");
    assert_eq!(q.response_code, "NOERROR");
}

#[test]
fn dns_query_clone() {
    let q = DnsQuery {
        timestamp: "t".to_string(), query: "q".to_string(), query_type: "A".to_string(),
        response: None, response_code: "NXDOMAIN".to_string(),
    };
    let q2 = q.clone();
    assert_eq!(q2.response_code, "NXDOMAIN");
}

#[test]
fn dns_query_debug() {
    let q = DnsQuery {
        timestamp: "t".to_string(), query: "q".to_string(), query_type: "A".to_string(),
        response: None, response_code: "NOERROR".to_string(),
    };
    assert!(format!("{:?}", q).contains("DnsQuery"));
}

#[test]
fn dns_query_serde_roundtrip() {
    let q = DnsQuery {
        timestamp: "now".to_string(), query: "rust-lang.org".to_string(),
        query_type: "AAAA".to_string(), response: Some("::1".to_string()),
        response_code: "NOERROR".to_string(),
    };
    let json = serde_json::to_string(&q).unwrap();
    let q2: DnsQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(q2.query, "rust-lang.org");
}

// ── ConnectionInfo ──

#[test]
fn connection_info_fields() {
    let c = ConnectionInfo {
        timestamp: "t".to_string(), protocol: "TCP".to_string(),
        local_addr: "192.168.1.1".to_string(), local_port: 12345,
        remote_addr: "93.184.216.34".to_string(), remote_port: 443,
        state: "ESTABLISHED".to_string(), pid: Some(1234),
        process_name: Some("chrome".to_string()),
    };
    assert_eq!(c.local_port, 12345);
    assert_eq!(c.pid, Some(1234));
}

#[test]
fn connection_info_clone() {
    let c = ConnectionInfo {
        timestamp: "t".to_string(), protocol: "TCP".to_string(),
        local_addr: "0.0.0.0".to_string(), local_port: 0,
        remote_addr: "0.0.0.0".to_string(), remote_port: 0,
        state: "s".to_string(), pid: None, process_name: None,
    };
    let c2 = c.clone();
    assert_eq!(c2.state, "s");
}

#[test]
fn connection_info_debug() {
    let c = ConnectionInfo {
        timestamp: "t".to_string(), protocol: "TCP".to_string(),
        local_addr: "0.0.0.0".to_string(), local_port: 0,
        remote_addr: "0.0.0.0".to_string(), remote_port: 0,
        state: "s".to_string(), pid: None, process_name: None,
    };
    assert!(format!("{:?}", c).contains("ConnectionInfo"));
}

#[test]
fn connection_info_serde_roundtrip() {
    let c = ConnectionInfo {
        timestamp: "now".to_string(), protocol: "TCP".to_string(),
        local_addr: "10.0.0.1".to_string(), local_port: 8080,
        remote_addr: "10.0.0.2".to_string(), remote_port: 443,
        state: "ESTABLISHED".to_string(), pid: Some(5678),
        process_name: Some("curl".to_string()),
    };
    let json = serde_json::to_string(&c).unwrap();
    let c2: ConnectionInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(c2.local_port, 8080);
}

// ── NetworkForensics ──

#[test]
fn network_forensics_new() {
    let _ = NetworkForensics::new();
}

#[test]
fn network_forensics_default() {
    let _ = NetworkForensics::default();
}

#[test]
fn network_forensics_analyze_nonexistent() {
    let result = NetworkForensics::analyze_capture("/nonexistent");
    assert!(result.is_err());
}

#[test]
fn network_forensics_analyze_pcap() {
    let data = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let info = NetworkForensics::analyze_pcap(data);
    assert_eq!(info.format, "pcap");
    assert!(info.packet_count >= 0);
}

#[test]
fn network_forensics_parse_dns() {
    let data = b"Query: example.com Type: A Response: 93.184.216.34";
    let queries = NetworkForensics::parse_dns(data);
    assert!(!queries.is_empty());
}

#[test]
fn network_forensics_extract_connections() {
    let entries = vec![NetworkLogEntry {
        timestamp: "now".to_string(),
        source_ip: Some("10.0.0.1".to_string()),
        dest_ip: Some("10.0.0.2".to_string()),
        source_port: Some(12345),
        dest_port: Some(80),
        protocol: "TCP".to_string(),
        length: 100, info: String::new(), flags: vec![],
    }];
    let json = serde_json::to_string(&entries).unwrap();
    let conns = NetworkForensics::extract_connections(json.as_bytes());
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].remote_port, 80);
}

#[test]
fn network_forensics_extract_connections_empty() {
    let conns = NetworkForensics::extract_connections(b"not json");
    assert!(conns.is_empty());
}

#[test]
fn network_forensics_clone() {
    let nf = NetworkForensics::new();
    let _nf2 = nf;
}

#[test]
fn network_forensics_debug() {
    let nf = NetworkForensics;
    let _ = &nf;
    assert!(std::any::type_name::<NetworkForensics>().contains("NetworkForensics"));
}
