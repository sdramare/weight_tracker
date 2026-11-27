use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use xiaomi_s200::Weight;

const MIN_INTERVAL_MS: i64 = 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WeightEntry {
    pub(super) measured_at_ms: i64,
    pub(super) weight: Weight,
}

struct History(Connection);

#[derive(Default)]
pub(super) struct HistoryMonitor {
    path: Option<PathBuf>,
    connection: Option<History>,
    data_version: Option<i64>,
}

impl HistoryMonitor {
    pub(super) fn refresh(&mut self) -> io::Result<Option<Vec<WeightEntry>>> {
        let previous = self.data_version;
        let connection = self.connection()?;
        let current = connection.data_version().map_err(io::Error::other)?;
        if previous == Some(current) {
            return Ok(None);
        }
        let entries = connection.entries().map_err(io::Error::other)?;
        self.data_version = Some(current);
        Ok(Some(entries))
    }

    pub(super) fn record(&mut self, weight: Weight) -> io::Result<Option<Vec<WeightEntry>>> {
        if self.connection()?.record(weight)?.is_some() {
            // SQLite data_version changes only for commits made by other connections.
            self.data_version = None;
        }
        self.refresh()
    }

    fn connection(&mut self) -> io::Result<&History> {
        match self.connection {
            Some(ref connection) => Ok(connection),
            None => {
                let path = match &self.path {
                    Some(path) => path,
                    None => self.path.insert(default_path()?),
                };
                Ok(self.connection.insert(History::open_at(path)?))
            }
        }
    }
}

impl History {
    fn open_at(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path).map_err(io::Error::other)?;
        Self::initialize(connection).map_err(io::Error::other)
    }

    fn initialize(connection: Connection) -> rusqlite::Result<Self> {
        connection.busy_timeout(Duration::from_millis(500))?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS weigh_ins (
                measured_at_ms INTEGER PRIMARY KEY,
                weight_hundredths_kg INTEGER NOT NULL CHECK (weight_hundredths_kg > 0)
            );",
        )?;
        Ok(Self(connection))
    }

    fn data_version(&self) -> rusqlite::Result<i64> {
        self.0
            .pragma_query_value(None, "data_version", |row| row.get(0))
    }

    fn entries(&self) -> rusqlite::Result<Vec<WeightEntry>> {
        let mut statement = self.0.prepare(
            "SELECT measured_at_ms, weight_hundredths_kg
             FROM weigh_ins
             ORDER BY measured_at_ms",
        )?;
        statement
            .query_map([], |row| {
                Ok(WeightEntry {
                    measured_at_ms: row.get(0)?,
                    weight: Weight::from_hundredths_of_kg(row.get(1)?),
                })
            })?
            .collect()
    }

    fn record(&self, weight: Weight) -> io::Result<Option<WeightEntry>> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        let measured_at_ms = i64::try_from(elapsed.as_millis()).map_err(io::Error::other)?;
        self.record_at(WeightEntry {
            measured_at_ms,
            weight,
        })
        .map_err(io::Error::other)
    }

    fn record_at(&self, entry: WeightEntry) -> rusqlite::Result<Option<WeightEntry>> {
        // Check eligibility and insert in one SQLite statement so concurrent windows
        // cannot both log a reading in the same 24-hour interval.
        let inserted = self.0.execute(
            "INSERT INTO weigh_ins (measured_at_ms, weight_hundredths_kg)
             SELECT ?1, ?2
             WHERE NOT EXISTS (
                 SELECT 1 FROM weigh_ins WHERE measured_at_ms >= ?1 - ?3
             )",
            params![
                entry.measured_at_ms,
                entry.weight.hundredths_of_kg(),
                MIN_INTERVAL_MS
            ],
        )?;
        Ok((inserted == 1).then_some(entry))
    }
}

fn default_path() -> io::Result<PathBuf> {
    let executable = std::env::current_exe()?;
    let repository = executable
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "target"))
        .and_then(Path::parent)
        .filter(|path| path.join("Cargo.toml").is_file());
    let directory = match repository {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir()?,
    };
    Ok(directory.join("data/weights.sqlite3"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{Connection, History, HistoryMonitor, MIN_INTERVAL_MS, Weight, WeightEntry};

    #[test]
    fn only_records_more_than_24_hours_after_the_last_entry() {
        let history = History::initialize(Connection::open_in_memory().unwrap()).unwrap();
        let entry_at = |measured_at_ms| WeightEntry {
            measured_at_ms,
            weight: Weight::from_hundredths_of_kg(7250),
        };
        let first = entry_at(1_000);
        let next = entry_at(first.measured_at_ms + MIN_INTERVAL_MS + 1);
        assert_eq!(history.record_at(first).unwrap(), Some(first));
        assert_eq!(
            history
                .record_at(entry_at(first.measured_at_ms + MIN_INTERVAL_MS))
                .unwrap(),
            None
        );
        assert_eq!(
            history
                .record_at(entry_at(first.measured_at_ms - 1))
                .unwrap(),
            None
        );
        assert_eq!(history.record_at(next).unwrap(), Some(next));
        assert_eq!(history.entries().unwrap(), [first, next]);
    }

    #[test]
    fn recovers_after_a_startup_lock_and_reloads_another_connection() {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("s200-history-{}-{id}.sqlite3", std::process::id()));
        let writer = History::open_at(&path).unwrap();
        writer.0.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let mut monitor = HistoryMonitor {
            path: Some(path.clone()),
            ..Default::default()
        };
        assert!(monitor.refresh().is_err());
        writer.0.execute_batch("ROLLBACK").unwrap();
        assert_eq!(monitor.refresh().unwrap(), Some(Vec::new()));

        let weight = Weight::from_hundredths_of_kg(7250);
        let first = writer.record(weight).unwrap().unwrap();
        assert_eq!(monitor.record(weight).unwrap(), Some(vec![first]));
        assert!(monitor.refresh().unwrap().is_none());
        let next = WeightEntry {
            measured_at_ms: first.measured_at_ms + MIN_INTERVAL_MS + 1,
            weight,
        };
        assert_eq!(writer.record_at(next).unwrap(), Some(next));
        assert_eq!(monitor.refresh().unwrap(), Some(vec![first, next]));
        drop(monitor);
        drop(writer);
        fs::remove_file(path).unwrap();
    }
}
