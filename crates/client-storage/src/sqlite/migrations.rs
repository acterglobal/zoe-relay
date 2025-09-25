use crate::error::{Result, StorageError};

// Embed migration files at compile time
mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("migrations");
}

/// Run all pending database migrations
pub fn run_migrations(conn: &mut rusqlite::Connection) -> Result<()> {
    tracing::debug!("Running SQLite schema migrations...");

    let report = embedded::migrations::runner()
        .run(conn)
        .map_err(|e| StorageError::Migration(format!("Migration failed: {e}")))?;

    for migration in report.applied_migrations() {
        tracing::trace!(
            "Applied migration: {} (version {})",
            migration.name(),
            migration.version()
        );
    }

    if report.applied_migrations().is_empty() {
        tracing::debug!("No migrations needed - database is up to date");
    } else {
        tracing::trace!(
            "Successfully applied {} migrations",
            report.applied_migrations().len()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_migrations_run_successfully() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut conn = rusqlite::Connection::open(temp_file.path()).unwrap();

        // Run migrations
        run_migrations(&mut conn).unwrap();

        // Verify tables were created
        let required_tables = [
            "messages",
            "storage_metadata",
            "tag_events",
            "tag_users",
            "tag_channels",
            "relay_sync_status",
        ];

        let table_names = required_tables
            .iter()
            .map(|name| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(",");

        let table_count: i32 = conn
            .prepare(&format!(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ({table_names})"
            ))
            .unwrap()
            .query_row([], |row| row.get(0))
            .unwrap();

        assert_eq!(
            table_count,
            required_tables.len() as i32,
            "Expected {} tables",
            required_tables.len()
        );

        // Verify metadata was inserted
        let metadata_count: i32 = conn
            .prepare("SELECT COUNT(*) FROM storage_metadata")
            .unwrap()
            .query_row([], |row| row.get(0))
            .unwrap();

        assert_eq!(metadata_count, 3, "Expected 3 metadata entries");
    }
}
