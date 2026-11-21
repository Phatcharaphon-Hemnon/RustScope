mod sealed;

use crate::domain::catalog;
use crate::model::{Project, Review, Scan};
use anyhow::{Result, anyhow, ensure};
use ring::aead::LessSafeKey;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{SqliteConnection, SqlitePool};
use std::{path::Path, sync::Arc};

#[derive(Clone)]
pub struct Store(SqlitePool, Arc<LessSafeKey>);

impl Store {
    pub async fn open(path: &Path) -> Result<Self> {
        let key = sealed::key(path)?;
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(include_str!("../migrations/0001_storage.sql"))
            .execute(&mut *tx)
            .await?;
        // shortcut: one active process per database, add job leases before sharing it.
        sqlx::query("UPDATE scans SET status = 'queued' WHERE status = 'running'")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Self(pool, Arc::new(key)))
    }

    pub async fn projects(&self, user: &str) -> Result<Vec<Project>> {
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT p.id, p.data FROM projects p JOIN members m ON m.project = p.id
             WHERE m.user = ? ORDER BY p.rowid",
        )
        .bind(user)
        .fetch_all(&self.0)
        .await?;
        rows.into_iter()
            .map(|(id, data)| self.decode_project(&id, &data))
            .collect()
    }

    pub async fn create(&self, user: &str, project: &Project) -> Result<()> {
        let mut stored = project.clone();
        stored.base = sealed::seal(&self.1, "project.base", &project.id, &project.base)?;
        let mut tx = self.0.begin().await?;
        sqlx::query("INSERT INTO projects (id, data) VALUES (?, ?)")
            .bind(&project.id)
            .bind(serde_json::to_string(&stored)?)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO members (project, user, role) VALUES (?, ?, 'owner')")
            .bind(&project.id)
            .bind(user)
            .execute(&mut *tx)
            .await?;
        audit(&mut tx, user, &project.id, "project_created", &project.id).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn access(&self, user: &str, id: &str) -> Result<(Project, String)> {
        self.project_access(&mut *self.0.acquire().await?, user, id)
            .await
    }

    pub async fn verify(&self, user: &str, id: &str) -> Result<()> {
        let mut tx = self.0.begin().await?;
        let (project, role) = self.project_access(&mut tx, user, id).await?;
        ensure!(role == "owner", "forbidden");
        ensure!(
            project.expires > now(&mut tx).await?,
            "scope is not verified or has expired"
        );
        sqlx::query(
            "UPDATE projects SET data = json_set(data, '$.verified', json('true')) WHERE id = ?",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        audit(&mut tx, user, id, "scope_verified", id).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn member(&self, user: &str, id: &str, other: &str, role: &str) -> Result<()> {
        ensure!(matches!(role, "reviewer" | "viewer"), "invalid member role");
        let mut tx = self.0.begin().await?;
        let (_, actor_role) = self.project_access(&mut tx, user, id).await?;
        ensure!(actor_role == "owner" && user != other, "forbidden");
        sqlx::query(
            "INSERT INTO members (project, user, role) VALUES (?, ?, ?)
             ON CONFLICT (project, user) DO UPDATE SET role = excluded.role
             WHERE members.role <> 'owner'",
        )
        .bind(id)
        .bind(other)
        .bind(role)
        .execute(&mut *tx)
        .await?;
        audit(&mut tx, user, id, role, other).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn scans(&self, user: &str, id: &str) -> Result<Vec<Scan>> {
        let mut tx = self.0.begin().await?;
        self.project_access(&mut tx, user, id).await?;
        let rows = sqlx::query_as::<_, (String, String, String)>(
            "SELECT id, data, status FROM scans WHERE project = ? ORDER BY rowid",
        )
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|(scan_id, data, status)| self.decode_scan(&scan_id, &data, status))
            .collect()
    }

    pub async fn reviews(&self, user: &str, id: &str, scan: &str) -> Result<Vec<Review>> {
        let mut tx = self.0.begin().await?;
        self.project_access(&mut tx, user, id).await?;
        ensure!(scan_exists(&mut tx, id, scan).await?, "scan not found");
        let rows =
            sqlx::query_scalar::<_, String>("SELECT data FROM reviews WHERE scan = ? ORDER BY id")
                .bind(scan)
                .fetch_all(&mut *tx)
                .await?;
        audit(&mut tx, user, id, "report_read", scan).await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|data| Ok(serde_json::from_str(&data)?))
            .collect()
    }

    pub async fn review(&self, user: &str, id: &str, review: &Review) -> Result<()> {
        let mut tx = self.0.begin().await?;
        let (_, role) = self.project_access(&mut tx, user, id).await?;
        ensure!(matches!(role.as_str(), "owner" | "reviewer"), "forbidden");
        ensure!(
            scan_exists(&mut tx, id, &review.scan).await?,
            "scan not found"
        );
        ensure!(
            catalog()
                .iter()
                .any(|rule| rule.id == review.rule && rule.method == "E"),
            "only evidence rules can be reviewed"
        );
        ensure!(
            matches!(
                review.decision.as_str(),
                "Finding" | "Review" | "Passed" | "Na" | "Insufficient"
            ) && !review.rationale.trim().is_empty()
                && !review.evidence.trim().is_empty(),
            "review decision, rationale, and evidence are required"
        );
        let mut saved = review.clone();
        saved.reviewer = user.to_owned();
        saved.at = now(&mut tx).await?;
        sqlx::query("INSERT INTO reviews (scan, data) VALUES (?, ?)")
            .bind(&saved.scan)
            .bind(serde_json::to_string(&saved)?)
            .execute(&mut *tx)
            .await?;
        audit(&mut tx, user, id, "review_recorded", &saved.scan).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn enqueue(
        &self,
        user: &str,
        id: &str,
        scan: &Scan,
        fixture: &str,
        request_id: &str,
    ) -> Result<String> {
        let mut tx = self.0.begin().await?;
        let (project, role) = self.project_access(&mut tx, user, id).await?;
        ensure!(role == "owner", "forbidden");
        ensure!(
            scan.project == id && !request_id.trim().is_empty(),
            "invalid scan request"
        );
        if let Some(existing) = sqlx::query_scalar(
            "SELECT id FROM scans WHERE project = ? AND requester = ? AND request_id = ?",
        )
        .bind(id)
        .bind(user)
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            return Ok(existing);
        }
        ensure!(
            project.verified && project.expires > now(&mut tx).await?,
            "scope is not verified or has expired"
        );
        let mut stored = scan.clone();
        stored.target = sealed::seal(&self.1, "scan.target", &scan.id, &scan.target)?;
        sqlx::query(
            "INSERT INTO scans (id, project, requester, request_id, fixture, status, data)
             VALUES (?, ?, ?, ?, ?, 'queued', ?)",
        )
        .bind(&scan.id)
        .bind(id)
        .bind(user)
        .bind(request_id)
        .bind(fixture)
        .bind(serde_json::to_string(&stored)?)
        .execute(&mut *tx)
        .await?;
        audit(&mut tx, user, id, "scan_queued", &scan.id).await?;
        tx.commit().await?;
        Ok(scan.id.clone())
    }

    pub(crate) async fn claim(&self) -> Result<Option<(Project, Scan, String)>> {
        let mut tx = self.0.begin().await?;
        let row = sqlx::query_as::<_, (String, String, String, String, String)>(
            "UPDATE scans SET status = 'running'
             WHERE rowid = (SELECT rowid FROM scans WHERE status = 'queued' ORDER BY rowid LIMIT 1)
             RETURNING id, project, data, fixture, (SELECT p.data FROM projects p WHERE p.id = scans.project)",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some((scan_id, project_id, scan, fixture, project)) = row else {
            return Ok(None);
        };
        let project = self.decode_project(&project_id, &project)?;
        let scan = self.decode_scan(&scan_id, &scan, "running".to_owned())?;
        tx.commit().await?;
        Ok(Some((project, scan, fixture)))
    }

    pub(crate) async fn finish(&self, scan: &Scan) -> Result<()> {
        ensure!(
            matches!(scan.status.as_str(), "complete" | "partial"),
            "invalid terminal scan status"
        );
        let result = sqlx::query(
            "UPDATE scans SET status = ?, data = json_set(data, '$.results', json(?), '$.observed_at', ?)
             WHERE id = ? AND project = ? AND status = 'running'",
        )
        .bind(&scan.status)
        .bind(serde_json::to_string(&scan.results)?)
        .bind(scan.observed_at)
        .bind(&scan.id)
        .bind(&scan.project)
        .execute(&self.0)
        .await?;
        ensure!(result.rows_affected() == 1, "scan is not running");
        Ok(())
    }

    async fn project_access(
        &self,
        conn: &mut SqliteConnection,
        user: &str,
        id: &str,
    ) -> Result<(Project, String)> {
        let (data, role) = sqlx::query_as::<_, (String, String)>(
            "SELECT p.data, m.role FROM projects p JOIN members m ON m.project = p.id
         WHERE p.id = ? AND m.user = ?",
        )
        .bind(id)
        .bind(user)
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| anyhow!("project not found"))?;
        Ok((self.decode_project(id, &data)?, role))
    }

    fn decode_scan(&self, id: &str, data: &str, status: String) -> Result<Scan> {
        let mut scan: Scan = serde_json::from_str(data)?;
        scan.target = sealed::open(&self.1, "scan.target", id, &scan.target)?;
        scan.status = status;
        Ok(scan)
    }

    fn decode_project(&self, id: &str, data: &str) -> Result<Project> {
        let mut project: Project = serde_json::from_str(data)?;
        project.base = sealed::open(&self.1, "project.base", id, &project.base)?;
        Ok(project)
    }
}

async fn scan_exists(conn: &mut SqliteConnection, project: &str, scan: &str) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM scans WHERE id = ? AND project = ?)")
            .bind(scan)
            .bind(project)
            .fetch_one(conn)
            .await?,
    )
}

async fn now(conn: &mut SqliteConnection) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT unixepoch()")
        .fetch_one(conn)
        .await?)
}

async fn audit(
    conn: &mut SqliteConnection,
    actor: &str,
    project: &str,
    action: &str,
    subject: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO audit (project, actor, action, subject) VALUES (?, ?, ?, ?)")
        .bind(project)
        .bind(actor)
        .bind(action)
        .bind(subject)
        .execute(conn)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Observation, Outcome};
    use crate::model::Policy;

    #[tokio::test]
    async fn queue_recovery_and_scoped_append_only_reviews() -> Result<()> {
        let path = std::env::temp_dir().join(format!("rustscope-{}.sqlite", uuid::Uuid::new_v4()));
        let result = exercise_store(&path).await;
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        let key_path = sealed::key_path(&path);
        if key_path.exists() {
            std::fs::remove_file(key_path)?;
        }
        result
    }

    async fn exercise_store(path: &Path) -> Result<()> {
        let store = Store::open(path).await?;
        let project = Project {
            id: "first".into(),
            name: "First".into(),
            base: "https://example.test/synthetic-secret-scope/".into(),
            expires: i64::MAX,
            challenge: "fixture-challenge".into(),
            verified: false,
            demo: false,
            upgrade: false,
        };
        store.create("owner", &project).await?;
        let mut other = project.clone();
        other.id = "second".into();
        store.create("reviewer", &other).await?;
        store
            .member("owner", "first", "reviewer", "reviewer")
            .await?;
        store.member("owner", "first", "viewer", "viewer").await?;
        assert_eq!(store.projects("viewer").await?.len(), 1);
        assert!(store.scans("viewer", "second").await.is_err());
        assert!(store.verify("reviewer", "first").await.is_err());
        assert!(
            store
                .member("viewer", "first", "new", "reviewer")
                .await
                .is_err()
        );
        let observation = Observation {
            rule: "A03-01".into(),
            item: "synthetic".into(),
            outcome: Outcome::Finding,
            observed: "redacted".into(),
        };
        let scan = Scan {
            id: "scan".into(),
            project: "first".into(),
            release: "v1.0".into(),
            environment: "test".into(),
            target: format!("{}synthetic-secret-target", project.base),
            policy: Policy {
                download: false,
                hsts_min: None,
                sri: false,
                expected_form: None,
            },
            version: "1".into(),
            at: 1,
            observed_at: 0,
            status: "queued".into(),
            results: vec![observation.clone()],
        };
        assert!(
            store
                .enqueue("owner", "first", &scan, "fixture", "retry")
                .await
                .is_err()
        );
        store.verify("owner", "first").await?;
        assert!(
            store
                .enqueue("reviewer", "first", &scan, "fixture", "retry")
                .await
                .is_err()
        );
        let mut duplicate = scan.clone();
        duplicate.id = "duplicate".into();
        let (first, retry) = tokio::join!(
            store.enqueue("owner", "first", &scan, "fixture", "retry"),
            store.enqueue("owner", "first", &duplicate, "fixture", "retry"),
        );
        let id = first?;
        assert_eq!(id, retry?);
        let (first, second) = tokio::join!(store.claim(), store.claim());
        let (_, job, _) = first?.xor(second?).expect("only one claim succeeds");
        assert_eq!(job.id, id);
        assert_eq!(job.status, "running");

        store.0.close().await;
        let persisted = std::fs::read(path)?;
        assert!(
            !persisted
                .windows(b"synthetic-secret".len())
                .any(|window| window == b"synthetic-secret")
        );
        let store = Store::open(path).await?;
        assert_eq!(store.scans("viewer", "first").await?[0].status, "queued");
        let (recovered_project, mut job, fixture) = store.claim().await?.expect("recovered job");
        assert_eq!(recovered_project.base, project.base);
        assert_eq!(job.target, scan.target);
        assert_eq!(fixture, "fixture");
        assert_eq!(job.results, vec![observation.clone()]);
        job.status = "partial".into();
        store.finish(&job).await?;
        assert!(store.finish(&job).await.is_err());

        let mut review = Review {
            scan: id.clone(),
            rule: "A01-04".into(),
            reviewer: "forged".into(),
            decision: "Review".into(),
            rationale: "needs confirmation".into(),
            evidence: "case 1".into(),
            at: 0,
        };
        assert!(store.review("viewer", "first", &review).await.is_err());
        assert!(store.review("reviewer", "second", &review).await.is_err());
        assert!(store.reviews("reviewer", "second", &id).await.is_err());
        store.review("reviewer", "first", &review).await?;
        review.decision = "Passed".into();
        store.review("reviewer", "first", &review).await?;
        let reviews = store.reviews("viewer", "first", &id).await?;
        assert_eq!(reviews.len(), 2);
        assert_eq!(reviews[0].decision, "Review");
        assert_eq!(reviews[0].reviewer, "reviewer");
        assert!(reviews[0].at > 0);
        let scans = store.scans("viewer", "first").await?;
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].target, scan.target);
        assert_eq!(scans[0].results, vec![observation]);
        assert_eq!(scans[0].status, "partial");
        let reads: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit WHERE action = 'report_read'")
                .fetch_one(&store.0)
                .await?;
        assert_eq!(reads, 1);
        store.0.close().await;
        std::fs::remove_file(sealed::key_path(path))?;
        let Err(error) = Store::open(path).await else {
            panic!("existing database without its key should fail to open");
        };
        assert!(
            error
                .to_string()
                .contains("storage encryption key is missing")
        );
        Ok(())
    }
}
