//! In-memory event bus for webhook-triggered channel notifications.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use domain::PublishableEvent;

use crate::api::AgentEventEnvelope;
use crate::config::AgentPolicyConfig;

const DEDUPE_TTL: Duration = Duration::from_secs(300);
const REPLAY_WINDOW_SIZE: usize = 32;
const SUBSCRIBER_BUFFER: usize = 32;

#[derive(Clone, Debug)]
pub struct EventBus {
    inner: Arc<Mutex<EventBusState>>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SubscriberKey {
    agent_id: String,
    subscriber_id: String,
}

#[derive(Clone, Debug)]
struct Subscriber {
    policy: AgentPolicyConfig,
    sender: mpsc::Sender<QueuedEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedEvent {
    pub data: String,
    pub envelope: AgentEventEnvelope,
    pub event_name: String,
    pub id: String,
}

#[derive(Debug)]
struct EventBusState {
    dedupe: HashMap<String, Instant>,
    next_synthetic_id: u64,
    replay: VecDeque<QueuedEvent>,
    subscribers: HashMap<SubscriberKey, Subscriber>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishStatus {
    Duplicate,
    Enqueued { delivered: usize },
}

impl EventBus {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(EventBusState {
                dedupe: HashMap::new(),
                next_synthetic_id: 0,
                replay: VecDeque::with_capacity(REPLAY_WINDOW_SIZE),
                subscribers: HashMap::new(),
            })),
        }
    }

    #[must_use]
    pub fn subscribe(
        &self,
        agent_id: String,
        policy: AgentPolicyConfig,
        subscriber_id: String,
        last_event_id: Option<&str>,
    ) -> mpsc::Receiver<QueuedEvent> {
        let key = SubscriberKey {
            agent_id,
            subscriber_id,
        };
        let (sender, receiver) = mpsc::channel(SUBSCRIBER_BUFFER);
        let (replay, replay_policy) = {
            let mut state = self.lock_state();
            let replay = state.replay_after(last_event_id);
            let replay_policy = policy.clone();
            state.subscribers.insert(
                key.clone(),
                Subscriber {
                    policy,
                    sender: sender.clone(),
                },
            );
            (replay, replay_policy)
        };

        for event in replay {
            if replay_policy.is_repo_allowed(
                &event.envelope.meta.forge_alias,
                &event.envelope.meta.owner,
                &event.envelope.meta.repo,
            ) {
                let _ = sender.try_send(event);
            }
        }

        let bus = self.clone();
        tokio::spawn(async move {
            sender.closed().await;
            bus.remove_subscriber(&key);
        });

        receiver
    }

    /// Publishes a normalized event to all authorized subscribers.
    ///
    /// # Errors
    ///
    /// Returns an error if the normalized event envelope cannot be serialized.
    pub fn publish<E: PublishableEvent>(&self, event: &E) -> Result<PublishStatus, String> {
        let channel_event = event.to_channel_event();
        let delivery_id = channel_event.meta.delivery_id.clone();
        let envelope = AgentEventEnvelope {
            content: channel_event.content,
            kind: event.event_name().to_string(),
            meta: channel_event.meta,
        };
        let data = serde_json::to_string(&envelope)
            .map_err(|e| format!("failed to serialize event: {e}"))?;

        let queued = {
            let mut state = self.lock_state();
            state.prune_dedupe();

            let dedupe_key = event.dedupe_key();
            if state.dedupe.contains_key(&dedupe_key) {
                return Ok(PublishStatus::Duplicate);
            }
            state.dedupe.insert(dedupe_key, Instant::now());

            let repo = event.repository_ref();
            let id = if delivery_id.is_empty() {
                state.next_synthetic_id += 1;
                format!("{}:synthetic:{}", repo.alias, state.next_synthetic_id)
            } else {
                format!("{}:{}", repo.alias, delivery_id)
            };

            let queued = QueuedEvent {
                data,
                envelope,
                event_name: event.event_name().to_string(),
                id,
            };
            state.push_replay(queued.clone());
            queued
        };

        let mut delivered = 0;
        let mut stale_subscribers = Vec::new();
        {
            let repo = event.repository_ref();
            let mut bus_state = self.lock_state();
            for (key, subscriber) in &bus_state.subscribers {
                if !subscriber
                    .policy
                    .is_repo_allowed(&repo.alias, &repo.owner, &repo.name)
                {
                    continue;
                }

                match subscriber.sender.try_send(queued.clone()) {
                    Ok(()) => {
                        delivered += 1;
                    }
                    Err(
                        mpsc::error::TrySendError::Full(_) | mpsc::error::TrySendError::Closed(_),
                    ) => {
                        stale_subscribers.push(key.clone());
                    }
                }
            }

            for key in stale_subscribers {
                bus_state.subscribers.remove(&key);
            }
        }

        Ok(PublishStatus::Enqueued { delivered })
    }

    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.lock_state().subscribers.len()
    }

    fn lock_state(&self) -> MutexGuard<'_, EventBusState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn remove_subscriber(&self, key: &SubscriberKey) {
        self.lock_state().subscribers.remove(key);
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBusState {
    fn prune_dedupe(&mut self) {
        let now = Instant::now();
        self.dedupe
            .retain(|_, seen_at| now.duration_since(*seen_at) < DEDUPE_TTL);
    }

    fn push_replay(&mut self, event: QueuedEvent) {
        self.replay.push_back(event);
        while self.replay.len() > REPLAY_WINDOW_SIZE {
            self.replay.pop_front();
        }
    }

    fn replay_after(&self, last_event_id: Option<&str>) -> Vec<QueuedEvent> {
        let Some(last_event_id) = last_event_id else {
            return Vec::new();
        };

        let Some(index) = self
            .replay
            .iter()
            .position(|event| event.id == last_event_id)
        else {
            return Vec::new();
        };

        self.replay.iter().skip(index + 1).cloned().collect()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use tokio::time::{Duration, timeout};

    use super::*;

    fn policy(allowed_repos: &[&str]) -> AgentPolicyConfig {
        AgentPolicyConfig {
            allowed_repos: allowed_repos.iter().map(ToString::to_string).collect(),
            branch_prefix: Some("agent/".to_string()),
            protected_paths: Vec::new(),
        }
    }

    fn change_request_event(
        action: domain::ChangeRequestEventAction,
        delivery_id: &str,
        head_sha: &str,
    ) -> domain::ChangeRequestEvent {
        change_request_event_for_repo(action, delivery_id, head_sha, "repo")
    }

    fn change_request_event_for_repo(
        action: domain::ChangeRequestEventAction,
        delivery_id: &str,
        head_sha: &str,
        repo: &str,
    ) -> domain::ChangeRequestEvent {
        domain::ChangeRequestEvent {
            action,
            delivery_id: delivery_id.to_string(),
            head_sha: head_sha.to_string(),
            index: 24,
            repository: domain::RepositoryRef {
                alias: "test-forge".to_string(),
                forge: domain::ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: repo.to_string(),
                owner: "org".to_string(),
            },
            title: "Fix".to_string(),
            url: "https://forge.example/org/repo/pulls/24".to_string(),
        }
    }

    #[tokio::test]
    async fn publishes_only_to_authorized_subscribers() {
        let bus = EventBus::new();
        let mut allowed = bus.subscribe(
            "codex".to_string(),
            policy(&["test-forge/org/repo"]),
            "sub-a".to_string(),
            None,
        );
        let mut denied = bus.subscribe(
            "claude".to_string(),
            policy(&["test-forge/other/repo"]),
            "sub-b".to_string(),
            None,
        );

        let status = bus
            .publish(&change_request_event(
                domain::ChangeRequestEventAction::Opened,
                "delivery-1",
                "abc123",
            ))
            .expect("publish should succeed");
        assert_eq!(status, PublishStatus::Enqueued { delivered: 1 });

        let event = timeout(Duration::from_secs(1), allowed.recv())
            .await
            .expect("timed out waiting for event")
            .expect("subscriber should remain connected");
        assert_eq!(event.event_name, "change_request");
        assert_eq!(event.envelope.meta.change_request, Some(24));

        let denied_event = timeout(Duration::from_millis(100), denied.recv()).await;
        assert!(denied_event.is_err());
    }

    #[tokio::test]
    async fn dedupe_suppresses_duplicate_deliveries() {
        let bus = EventBus::new();
        let mut receiver = bus.subscribe(
            "codex".to_string(),
            policy(&["test-forge/org/repo"]),
            "sub-a".to_string(),
            None,
        );

        let first = bus
            .publish(&change_request_event(
                domain::ChangeRequestEventAction::Opened,
                "delivery-1",
                "abc123",
            ))
            .expect("first publish should succeed");
        assert_eq!(first, PublishStatus::Enqueued { delivered: 1 });

        let second = bus
            .publish(&change_request_event(
                domain::ChangeRequestEventAction::Opened,
                "delivery-1",
                "abc123",
            ))
            .expect("second publish should succeed");
        assert_eq!(second, PublishStatus::Duplicate);

        let _ = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("timed out waiting for first event")
            .expect("first event missing");
        let duplicate = timeout(Duration::from_millis(100), receiver.recv()).await;
        assert!(duplicate.is_err());
    }

    #[tokio::test]
    async fn replays_events_after_last_seen_id() {
        let bus = EventBus::new();

        bus.publish(&change_request_event(
            domain::ChangeRequestEventAction::Opened,
            "delivery-1",
            "abc123",
        ))
        .expect("publish should succeed");
        bus.publish(&change_request_event(
            domain::ChangeRequestEventAction::Synchronized,
            "delivery-2",
            "def456",
        ))
        .expect("publish should succeed");

        let mut receiver = bus.subscribe(
            "codex".to_string(),
            policy(&["test-forge/org/repo"]),
            "sub-a".to_string(),
            Some("test-forge:delivery-1"),
        );

        let replay = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("timed out waiting for replay event")
            .expect("replay event missing");
        assert_eq!(replay.id, "test-forge:delivery-2");
        assert_eq!(replay.envelope.meta.head_sha.as_deref(), Some("def456"));
    }

    #[tokio::test]
    async fn replay_filters_unauthorized_events() {
        let bus = EventBus::new();

        bus.publish(&change_request_event(
            domain::ChangeRequestEventAction::Opened,
            "delivery-0",
            "aaa111",
        ))
        .expect("publish should succeed");
        bus.publish(&change_request_event_for_repo(
            domain::ChangeRequestEventAction::Opened,
            "delivery-1",
            "bbb222",
            "other",
        ))
        .expect("publish should succeed");
        bus.publish(&change_request_event(
            domain::ChangeRequestEventAction::Synchronized,
            "delivery-2",
            "ccc333",
        ))
        .expect("publish should succeed");

        let mut receiver = bus.subscribe(
            "codex".to_string(),
            policy(&["test-forge/org/repo"]),
            "sub-a".to_string(),
            Some("test-forge:delivery-0"),
        );

        let replay = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("timed out waiting for replay event")
            .expect("replay event missing");
        assert_eq!(replay.id, "test-forge:delivery-2");
        assert_eq!(replay.envelope.meta.repo, "repo");

        let extra = timeout(Duration::from_millis(100), receiver.recv()).await;
        assert!(extra.is_err());
    }

    #[tokio::test]
    async fn publishes_issue_event_to_authorized_subscribers() {
        let bus = EventBus::new();
        let mut receiver = bus.subscribe(
            "codex".to_string(),
            policy(&["test-forge/org/repo"]),
            "sub-a".to_string(),
            None,
        );

        let event = domain::IssueEvent {
            action: domain::IssueEventAction::Opened,
            delivery_id: "delivery-issue-1".to_string(),
            index: 42,
            repository: domain::RepositoryRef {
                alias: "test-forge".to_string(),
                forge: domain::ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                name: "repo".to_string(),
                owner: "org".to_string(),
            },
            title: "Bug".to_string(),
            url: "https://forge.example/org/repo/issues/42".to_string(),
        };

        let status = bus.publish(&event).expect("publish should succeed");
        assert_eq!(status, PublishStatus::Enqueued { delivered: 1 });

        let queued = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("timed out")
            .expect("connected");
        assert_eq!(queued.event_name, "issue");
        assert_eq!(queued.envelope.meta.issue, Some(42));
        assert_eq!(queued.envelope.meta.change_request, None);
    }
}
