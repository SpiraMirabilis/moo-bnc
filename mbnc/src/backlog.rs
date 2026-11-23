//! Output buffered while no client is attached.
//!
//! Entries are kept in memory until `memory_bytes` is exceeded, then appended
//! to `<dir>/backlog.bin`. When that file passes `disk_bytes` it is rotated to
//! `backlog.1.bin` (replacing any previous one, which marks the backlog as
//! truncated). Draining replays `backlog.1.bin`, `backlog.bin`, then memory.
//!
//! On-disk record: `kind: u8 | ts_ms: i64 BE | len: u32 BE | bytes`.

use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

const KIND_DATA: u8 = 0;
const KIND_NOTICE: u8 = 1;
/// Consecutive data arriving within this window is merged into one entry.
const COALESCE_MS: i64 = 1000;
const COALESCE_MAX: usize = 32 * 1024;
const MAX_RECORD: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Data { ts_ms: i64, bytes: Vec<u8> },
    Notice { ts_ms: i64, text: String },
}

impl Entry {
    fn len(&self) -> usize {
        match self {
            Entry::Data { bytes, .. } => bytes.len(),
            Entry::Notice { text, .. } => text.len(),
        }
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        let (kind, ts, body): (u8, i64, &[u8]) = match self {
            Entry::Data { ts_ms, bytes } => (KIND_DATA, *ts_ms, bytes),
            Entry::Notice { ts_ms, text } => (KIND_NOTICE, *ts_ms, text.as_bytes()),
        };
        out.push(kind);
        out.extend_from_slice(&ts.to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
    }
}

pub struct Backlog {
    dir: PathBuf,
    mem: VecDeque<Entry>,
    mem_bytes: usize,
    mem_limit: usize,
    disk_limit: u64,
    cur_bytes: u64,
    old_bytes: u64,
    truncated: bool,
}

impl Backlog {
    pub fn open(dir: &Path, mem_limit: usize, disk_limit: u64) -> io::Result<Backlog> {
        std::fs::create_dir_all(dir)?;
        let size = |p: PathBuf| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        Ok(Backlog {
            dir: dir.to_path_buf(),
            mem: VecDeque::new(),
            mem_bytes: 0,
            mem_limit,
            disk_limit: disk_limit.max(1),
            cur_bytes: size(dir.join("backlog.bin")),
            old_bytes: size(dir.join("backlog.1.bin")),
            truncated: false,
        })
    }

    fn cur_path(&self) -> PathBuf {
        self.dir.join("backlog.bin")
    }

    fn old_path(&self) -> PathBuf {
        self.dir.join("backlog.1.bin")
    }

    /// Approximate bytes waiting (payload in memory + file sizes on disk).
    pub fn total_bytes(&self) -> u64 {
        self.mem_bytes as u64 + self.cur_bytes + self.old_bytes
    }

    pub async fn push_data(&mut self, ts_ms: i64, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Some(Entry::Data { ts_ms: last_ts, bytes: last }) = self.mem.back_mut() {
            if ts_ms - *last_ts < COALESCE_MS && last.len() + bytes.len() <= COALESCE_MAX {
                last.extend_from_slice(bytes);
                self.mem_bytes += bytes.len();
                self.maybe_spill().await;
                return;
            }
        }
        self.push(Entry::Data { ts_ms, bytes: bytes.to_vec() }).await;
    }

    pub async fn push_notice(&mut self, ts_ms: i64, text: String) {
        self.push(Entry::Notice { ts_ms, text }).await;
    }

    async fn push(&mut self, e: Entry) {
        self.mem_bytes += e.len();
        self.mem.push_back(e);
        self.maybe_spill().await;
    }

    async fn maybe_spill(&mut self) {
        if self.mem_bytes > self.mem_limit {
            if let Err(e) = self.spill().await {
                // Keep the data in memory and try again next time.
                tracing::error!(dir = %self.dir.display(), "spilling backlog to disk failed: {e}");
            }
        }
    }

    /// Write everything in memory to disk.
    pub async fn spill(&mut self) -> io::Result<()> {
        if self.mem.is_empty() {
            return Ok(());
        }
        let mut buf = Vec::with_capacity(self.mem_bytes + self.mem.len() * 13);
        for e in &self.mem {
            e.write_to(&mut buf);
        }
        let mut f = fs::OpenOptions::new().create(true).append(true).open(self.cur_path()).await?;
        f.write_all(&buf).await?;
        f.flush().await?;
        self.cur_bytes += buf.len() as u64;
        self.mem.clear();
        self.mem_bytes = 0;
        if self.cur_bytes > self.disk_limit {
            if self.old_bytes > 0 {
                self.truncated = true;
            }
            fs::rename(self.cur_path(), self.old_path()).await?;
            self.old_bytes = self.cur_bytes;
            self.cur_bytes = 0;
        }
        Ok(())
    }

    /// Take everything for replay, leaving the backlog empty.
    pub fn take(&mut self) -> Drain {
        let mut files = Vec::new();
        if self.old_bytes > 0 {
            files.push(self.old_path());
        }
        if self.cur_bytes > 0 {
            files.push(self.cur_path());
        }
        let d = Drain {
            files: files.into(),
            reader: None,
            mem: std::mem::take(&mut self.mem),
            truncated: self.truncated,
            done_files: Vec::new(),
        };
        self.mem_bytes = 0;
        self.cur_bytes = 0;
        self.old_bytes = 0;
        self.truncated = false;
        d
    }

    /// Delete everything, including the directory.
    pub async fn destroy(&mut self) {
        self.take();
        let _ = fs::remove_dir_all(&self.dir).await;
    }
}

/// Sequential reader over a taken backlog. Files are deleted by [`Drain::finish`].
pub struct Drain {
    files: VecDeque<PathBuf>,
    reader: Option<BufReader<fs::File>>,
    mem: VecDeque<Entry>,
    pub truncated: bool,
    done_files: Vec<PathBuf>,
}

impl Drain {
    pub async fn next(&mut self) -> io::Result<Option<Entry>> {
        loop {
            if let Some(r) = self.reader.as_mut() {
                match read_record(r).await? {
                    Some(e) => return Ok(Some(e)),
                    None => self.reader = None,
                }
            }
            match self.files.pop_front() {
                Some(p) => {
                    match fs::File::open(&p).await {
                        Ok(f) => self.reader = Some(BufReader::new(f)),
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e),
                    }
                    self.done_files.push(p);
                }
                None => return Ok(self.mem.pop_front()),
            }
        }
    }

    /// Remove the backing files. Call after replay (successful or not).
    pub async fn finish(mut self) {
        self.reader = None;
        self.done_files.extend(self.files.drain(..));
        for p in self.done_files {
            if let Err(e) = fs::remove_file(&p).await {
                if e.kind() != io::ErrorKind::NotFound {
                    tracing::warn!("removing {}: {e}", p.display());
                }
            }
        }
    }
}

async fn read_record(r: &mut BufReader<fs::File>) -> io::Result<Option<Entry>> {
    let mut hdr = [0u8; 13];
    match r.read_exact(&mut hdr[..1]).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    if let Err(e) = r.read_exact(&mut hdr[1..]).await {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            tracing::warn!("truncated backlog record header; ignoring rest of file");
            return Ok(None);
        }
        return Err(e);
    }
    let ts_ms = i64::from_be_bytes(hdr[1..9].try_into().unwrap());
    let len = u32::from_be_bytes(hdr[9..13].try_into().unwrap()) as usize;
    if len > MAX_RECORD {
        tracing::warn!("corrupt backlog record (len {len}); ignoring rest of file");
        return Ok(None);
    }
    let mut body = vec![0u8; len];
    if let Err(e) = r.read_exact(&mut body).await {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            tracing::warn!("truncated backlog record; ignoring rest of file");
            return Ok(None);
        }
        return Err(e);
    }
    Ok(Some(match hdr[0] {
        KIND_NOTICE => Entry::Notice { ts_ms, text: String::from_utf8_lossy(&body).into_owned() },
        _ => Entry::Data { ts_ms, bytes: body },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn drain_all(b: &mut Backlog) -> (Vec<Entry>, bool) {
        let mut d = b.take();
        let mut v = Vec::new();
        while let Some(e) = d.next().await.unwrap() {
            v.push(e);
        }
        let t = d.truncated;
        d.finish().await;
        (v, t)
    }

    #[tokio::test]
    async fn memory_only_with_coalescing() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = Backlog::open(dir.path(), 1 << 20, 1 << 20).unwrap();
        b.push_data(1000, b"ab").await;
        b.push_data(1500, b"cd").await;
        b.push_notice(1600, "hi".into()).await;
        b.push_data(5000, b"ef").await;
        let (v, t) = drain_all(&mut b).await;
        assert!(!t);
        assert_eq!(
            v,
            vec![
                Entry::Data { ts_ms: 1000, bytes: b"abcd".to_vec() },
                Entry::Notice { ts_ms: 1600, text: "hi".into() },
                Entry::Data { ts_ms: 5000, bytes: b"ef".to_vec() },
            ]
        );
        assert_eq!(b.total_bytes(), 0);
    }

    #[tokio::test]
    async fn spills_and_rotates_in_order() {
        let dir = tempfile::tempdir().unwrap();
        // tiny limits: every push spills, every ~3 records rotate
        let mut b = Backlog::open(dir.path(), 4, 40).unwrap();
        for i in 0..20i64 {
            b.push_data(i * 10_000, format!("line{i:02}").as_bytes()).await;
        }
        b.push_data(999_999, b"x").await; // stays in memory (under limit)
        let (v, truncated) = drain_all(&mut b).await;
        assert!(truncated);
        let texts: Vec<String> = v
            .iter()
            .map(|e| match e {
                Entry::Data { bytes, .. } => String::from_utf8(bytes.clone()).unwrap(),
                _ => panic!(),
            })
            .collect();
        // Newest data is always retained and order is preserved.
        assert_eq!(texts.last().unwrap(), "x");
        assert_eq!(texts[texts.len() - 2], "line19");
        let mut sorted = texts.clone();
        sorted.sort();
        assert_eq!(sorted, texts);
        assert!(!dir.path().join("backlog.bin").exists());
        assert!(!dir.path().join("backlog.1.bin").exists());
    }

    #[tokio::test]
    async fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut b = Backlog::open(dir.path(), 1 << 20, 1 << 20).unwrap();
            b.push_data(1, b"persisted").await;
            b.spill().await.unwrap();
        }
        let mut b = Backlog::open(dir.path(), 1 << 20, 1 << 20).unwrap();
        assert!(b.total_bytes() > 0);
        let (v, _) = drain_all(&mut b).await;
        assert_eq!(v, vec![Entry::Data { ts_ms: 1, bytes: b"persisted".to_vec() }]);
    }
}
