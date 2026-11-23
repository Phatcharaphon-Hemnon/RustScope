use crate::{auth::now, model::Scan};
use anyhow::anyhow;
use std::{collections::HashMap, sync::Mutex};

const MAX_DRAFTS: usize = 64;
const DRAFT_LIFETIME: i64 = 3600;
type DraftKey = (String, String, String);

#[derive(Clone)]
pub(crate) struct Draft {
    pub scan: Scan,
    pub fixture: String,
    pub lockfile_used: bool,
}

#[derive(Default)]
pub(crate) struct Previews(Mutex<HashMap<DraftKey, Draft>>);

impl Previews {
    pub fn remember(&self, session: &str, request: &str, draft: Draft) -> anyhow::Result<()> {
        let key = (session.into(), draft.scan.project.clone(), request.into());
        let mut drafts = self.0.lock().map_err(|_| anyhow!("preview store locked"))?;
        let cutoff = now() - DRAFT_LIFETIME;
        drafts.retain(|_, draft| draft.scan.at > cutoff);
        if drafts.len() >= MAX_DRAFTS
            && !drafts.contains_key(&key)
            && let Some(oldest) = drafts.iter().min_by_key(|(_, draft)| draft.scan.at)
        {
            let oldest = oldest.0.clone();
            drafts.remove(&oldest);
        }
        drafts.insert(key, draft);
        Ok(())
    }

    pub fn get(
        &self,
        session: &str,
        project: &str,
        request: &str,
    ) -> anyhow::Result<Option<Draft>> {
        let drafts = self.0.lock().map_err(|_| anyhow!("preview store locked"))?;
        Ok(drafts
            .get(&(session.into(), project.into(), request.into()))
            .filter(|draft| draft.scan.at > now() - DRAFT_LIFETIME)
            .cloned())
    }
}
