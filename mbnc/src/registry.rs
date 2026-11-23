//! All sessions, keyed by id and by (host, port, character). Session specs
//! are persisted to `<data_dir>/sessions.json` so they are re-established
//! after a proxy restart.

use crate::config::Config;
use crate::session::{self, SessionHandle, SessionKey, SessionSpec};
use anyhow::{bail, Context, Result};
use mbnc_proto::{LoginStep, SessionId, TelnetPrefs, World};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Default, Serialize, Deserialize)]
struct Persisted {
    next_id: SessionId,
    sessions: Vec<SessionSpec>,
}

struct Inner {
    specs: BTreeMap<SessionId, SessionSpec>,
    handles: HashMap<SessionId, SessionHandle>,
    by_key: HashMap<SessionKey, SessionId>,
    next_id: SessionId,
}

pub struct Registry {
    cfg: Arc<Config>,
    inner: Mutex<Inner>,
}

pub enum Opened {
    Created(SessionHandle),
    /// Existing session; the merged spec must be pushed to the actor.
    Existing(SessionHandle, SessionSpec),
}

impl Registry {
    fn path(&self) -> PathBuf {
        self.cfg.data_dir.join("sessions.json")
    }

    /// Load persisted sessions and start them. Must run inside a tokio runtime.
    pub fn load(cfg: Arc<Config>) -> Result<Arc<Registry>> {
        create_private_dir(&cfg.data_dir)?;
        let reg = Arc::new(Registry {
            cfg: cfg.clone(),
            inner: Mutex::new(Inner {
                specs: BTreeMap::new(),
                handles: HashMap::new(),
                by_key: HashMap::new(),
                next_id: 1,
            }),
        });
        let path = reg.path();
        let persisted: Persisted = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("parsing {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Persisted::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        {
            let mut inner = reg.inner.lock().unwrap();
            inner.next_id = persisted.next_id.max(1);
            for spec in persisted.sessions {
                inner.next_id = inner.next_id.max(spec.id + 1);
                let handle = session::spawn(spec.clone(), cfg.clone())?;
                inner.by_key.insert(spec.key(), spec.id);
                inner.handles.insert(spec.id, handle);
                inner.specs.insert(spec.id, spec);
            }
            tracing::info!(count = inner.specs.len(), "loaded sessions");
        }
        Ok(reg)
    }

    pub fn open(
        &self,
        world: World,
        character: String,
        login: Option<Vec<LoginStep>>,
        telnet: Option<TelnetPrefs>,
    ) -> Result<Opened> {
        if world.host.trim().is_empty() {
            bail!("world.host must not be empty");
        }
        if world.port == 0 {
            bail!("world.port must not be 0");
        }
        if character.trim().is_empty() {
            bail!("character must not be empty");
        }
        let key = SessionKey::new(&world, &character);
        let mut inner = self.inner.lock().unwrap();
        if let Some(&id) = inner.by_key.get(&key) {
            let spec = inner.specs.get_mut(&id).expect("spec for key");
            spec.world = world;
            spec.character = character;
            if let Some(l) = login {
                spec.login = l;
            }
            if let Some(t) = telnet {
                spec.telnet = t;
            }
            let spec = spec.clone();
            let handle = inner.handles[&id].clone();
            self.persist(&inner)?;
            return Ok(Opened::Existing(handle, spec));
        }
        let id = inner.next_id;
        inner.next_id += 1;
        let spec = SessionSpec {
            id,
            world,
            character,
            login: login.unwrap_or_default(),
            telnet: telnet.unwrap_or_default(),
        };
        let handle = session::spawn(spec.clone(), self.cfg.clone())?;
        inner.by_key.insert(key, id);
        inner.handles.insert(id, handle.clone());
        inner.specs.insert(id, spec);
        self.persist(&inner)?;
        Ok(Opened::Created(handle))
    }

    pub fn get(&self, id: SessionId) -> Option<SessionHandle> {
        self.inner.lock().unwrap().handles.get(&id).cloned()
    }

    pub fn all(&self) -> Vec<SessionHandle> {
        self.inner.lock().unwrap().handles.values().cloned().collect()
    }

    /// Forget a session. The caller is responsible for closing the actor.
    pub fn remove(&self, id: SessionId) -> Result<Option<SessionHandle>> {
        let mut inner = self.inner.lock().unwrap();
        let Some(spec) = inner.specs.remove(&id) else { return Ok(None) };
        inner.by_key.remove(&spec.key());
        let h = inner.handles.remove(&id);
        self.persist(&inner)?;
        Ok(h)
    }

    fn persist(&self, inner: &Inner) -> Result<()> {
        let p = Persisted { next_id: inner.next_id, sessions: inner.specs.values().cloned().collect() };
        let json = serde_json::to_vec_pretty(&p)?;
        let path = self.path();
        let tmp = path.with_extension("json.tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }
}

/// sessions.json holds login credentials, so keep the data dir private.
fn create_private_dir(dir: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}
