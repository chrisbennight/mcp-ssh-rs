//! Storage budgets, retained commitments, and active receipt accounting.

use super::*;

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub entries: usize,
    pub readable_bytes: usize,
    pub readable_millis: u64,
    pub active_proofs: usize,
    pub proof_bytes: usize,
    pub evaluation_ids: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            entries: 4096,
            readable_bytes: 16 << 20,
            readable_millis: 3_600_000,
            active_proofs: 1024,
            proof_bytes: 16 << 20,
            evaluation_ids: 65_536,
        }
    }
}

pub(super) struct State {
    pub entries: VecDeque<Held>,
    pub issued: Issued,
    pub evaluations: EvaluationIndex,
    pub proofs: HashMap<u64, Weak<Proof>>,
    pub readable_bytes: usize,
    sizes: VecDeque<usize>,
}

pub(super) struct Written {
    pub entry: Arc<Entry>,
    pub proof: Option<Arc<Proof>>,
}

pub(super) struct Prepared {
    bytes: usize,
    readable: bool,
}

impl State {
    pub fn new(genesis: Digest) -> Self {
        Self {
            entries: VecDeque::new(),
            issued: Issued {
                digests: VecDeque::new(),
                retired: 0,
                total: 0,
                checkpoint: genesis,
            },
            evaluations: EvaluationIndex::default(),
            proofs: HashMap::new(),
            readable_bytes: 0,
            sizes: VecDeque::new(),
        }
    }

    pub fn get(&self, sequence: u64) -> Option<&Held> {
        let index = usize::try_from(sequence.checked_sub(self.issued.retired)?).ok()?;
        self.entries.get(index)
    }

    pub fn active_proof(&self, sequence: u64) -> Option<Arc<Proof>> {
        self.proofs.get(&sequence)?.upgrade()
    }

    pub fn reclaim(&mut self, now: Millis, limits: Limits) -> Result<(), AuditError> {
        if self.entries.len() != self.issued.digests.len()
            || self.entries.len() != self.sizes.len()
            || self.issued.retired.checked_add(self.entries.len() as u64) != Some(self.issued.total)
        {
            return Err(AuditError::RetentionCorrupt);
        }
        for index in 0..self.entries.len() {
            if self.entries.get(index).is_some_and(|held| match held {
                Held::Intact(entry) => now.saturating_sub(entry.at) >= limits.readable_millis,
                Held::Sealed { .. } => false,
            }) {
                self.seal(index)?;
            }
        }
        self.prune_indexes();
        Ok(())
    }

    /// Reserve space before the required sink write or issuance of authority.
    pub fn prepare(
        &mut self,
        now: Millis,
        limits: Limits,
        entry: &Entry,
        pin: bool,
    ) -> Result<Prepared, AuditError> {
        self.issued.total.checked_add(1).ok_or(AuditError::Full)?;
        let bytes = encoded_bytes(entry)?;
        self.reclaim(now, limits)?;
        let readable = bytes <= limits.readable_bytes;
        if limits.entries == 0 || (pin && !readable) {
            return Err(AuditError::Full);
        }
        if pin {
            let pinned = self
                .proofs
                .values()
                .filter_map(Weak::upgrade)
                .fold(0_usize, |sum, proof| sum.saturating_add(proof.bytes));
            if self.proofs.len() >= limits.active_proofs
                || pinned
                    .checked_add(bytes)
                    .is_none_or(|total| total > limits.proof_bytes)
            {
                return Err(AuditError::Full);
            }
        }
        while self.entries.len() >= limits.entries {
            self.retire_front()?;
        }
        // An oversized outcome must still cross the required recording
        // boundary. Keep its commitment without retaining its readable body.
        let charge = if readable { bytes } else { 0 };
        for index in 0..self.entries.len() {
            if self
                .readable_bytes
                .checked_add(charge)
                .is_some_and(|total| total <= limits.readable_bytes)
            {
                break;
            }
            self.seal(index)?;
        }
        if self
            .readable_bytes
            .checked_add(charge)
            .is_none_or(|total| total > limits.readable_bytes)
        {
            return Err(AuditError::Full);
        }
        self.prune_indexes();
        Ok(Prepared { bytes, readable })
    }

    pub fn commit(
        &mut self,
        entry: Entry,
        prepared: Prepared,
        pin: bool,
    ) -> Result<Written, AuditError> {
        let total = self.issued.total.checked_add(1).ok_or(AuditError::Full)?;
        let entry = Arc::new(entry);
        self.issued.digests.push_back(entry.digest.clone());
        self.issued.total = total;
        let charge = if prepared.readable { prepared.bytes } else { 0 };
        self.sizes.push_back(charge);
        self.readable_bytes = self.readable_bytes.saturating_add(charge);
        self.entries.push_back(if prepared.readable {
            Held::Intact(Arc::clone(&entry))
        } else {
            Held::Sealed {
                sequence: entry.sequence,
                previous: entry.previous.clone(),
                digest: entry.digest.clone(),
            }
        });
        let proof = pin.then(|| {
            let proof = Arc::new(Proof {
                entry: Arc::clone(&entry),
                bytes: prepared.bytes,
                completed: AtomicBool::new(false),
            });
            self.proofs.insert(entry.sequence, Arc::downgrade(&proof));
            proof
        });
        Ok(Written { entry, proof })
    }

    pub fn seal(&mut self, index: usize) -> Result<(), AuditError> {
        self.check(index)?;
        if let Some(held @ Held::Intact(_)) = self.entries.get_mut(index) {
            let Held::Intact(entry) = held else {
                return Err(AuditError::RetentionCorrupt);
            };
            *held = Held::Sealed {
                sequence: entry.sequence,
                previous: entry.previous.clone(),
                digest: entry.digest.clone(),
            };
            if let Some(bytes) = self.sizes.get_mut(index) {
                self.readable_bytes = self.readable_bytes.saturating_sub(*bytes);
                *bytes = 0;
            }
        }
        Ok(())
    }

    fn check(&self, index: usize) -> Result<(), AuditError> {
        let held = self
            .entries
            .get(index)
            .ok_or(AuditError::RetentionCorrupt)?;
        let sequence = self
            .issued
            .retired
            .checked_add(index as u64)
            .ok_or(AuditError::RetentionCorrupt)?;
        let previous = index
            .checked_sub(1)
            .and_then(|before| self.entries.get(before))
            .map_or(&self.issued.checkpoint, Held::digest);
        if held.sequence() != sequence
            || held.previous() != previous
            || self.issued.digests.get(index) != Some(held.digest())
        {
            return Err(AuditError::RetentionCorrupt);
        }
        if let Held::Intact(entry) = held
            && digest_of(entry)? != entry.digest
        {
            return Err(AuditError::RetentionCorrupt);
        }
        Ok(())
    }

    fn retire_front(&mut self) -> Result<(), AuditError> {
        self.check(0)?;
        let retired = self.issued.retired.checked_add(1).ok_or(AuditError::Full)?;
        let held = self
            .entries
            .pop_front()
            .ok_or(AuditError::RetentionCorrupt)?;
        self.issued.checkpoint = held.digest().clone();
        self.issued.retired = retired;
        self.issued.digests.pop_front();
        self.readable_bytes = self
            .readable_bytes
            .saturating_sub(self.sizes.pop_front().unwrap_or(0));
        Ok(())
    }

    pub fn prune_indexes(&mut self) {
        self.proofs.retain(|_, proof| proof.strong_count() > 0);
        let first = self.issued.retired;
        let entries = &self.entries;
        let readable = |sequence: u64| {
            sequence
                .checked_sub(first)
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| entries.get(index))
                .is_some_and(|held| matches!(held, Held::Intact(_)))
        };
        self.evaluations
            .readable_decisions
            .retain(|_, decision| readable(decision.sequence));
        self.evaluations
            .readable_artifacts
            .retain(|_, entry| readable(entry.sequence));
    }
}

fn encoded_bytes(entry: &Entry) -> Result<usize, AuditError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("audit size overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, entry).map_err(|_| AuditError::Full)?;
    Ok(counter.0)
}
