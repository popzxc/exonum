// Copyright 2019 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The module containing interfaces to request changes in the blockchain structure.

mod blockchain_secretary;

pub use blockchain_secretary::{BlockchainSecretary, MailboxContext};

use std::cell::RefCell;

use crate::runtime::{ArtifactId, ConfigChange, InstanceId, InstanceSpec};

/// Optional callback to be called after request is completed by the blockchain core.
pub type AfterRequestCompleted = Option<Box<dyn FnOnce() + 'static>>;

/// An interface for runtimes to interact with the Exonum blockchain core.
///
/// All the requests added to the mailbox will be processed by the core `Blockchain` structure.
///
/// **Important note:** All the requests received after the transaction execution are considered
/// **the part of execution process**. So, if service requests blockchain to perform some action
/// and an error occurs during the request processing, the transaction will be treated as failed
/// and, as a result, rolled back.
///
/// **Policy on request failures:**
///
/// Services **will not** be notified if request was failed or ignored. So it's up to the service
/// implementors to build the logic in such a way that lack of result will not break the service
/// state.
///
/// Services are able to provide `AfterRequestCompleted` callback and consider the situation when
/// callback is not called at the some point of time as failed/ignored request.
#[derive(Default)]
pub struct BlockchainMailbox {
    requests: RefCell<Vec<(Action, AfterRequestCompleted)>>,
    notifications: Vec<Notification>,
}

impl std::fmt::Debug for BlockchainMailbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlockchainMailbox")
    }
}

impl BlockchainMailbox {
    /// Creates a new empty mailbox.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a request for action to the mailbox.
    pub fn add_request(&self, action: Action, and_then: AfterRequestCompleted) {
        let mut requests = self.requests.borrow_mut();
        requests.push((action, and_then));
    }

    /// Adds a notification about completed event to the mailbox.
    fn add_notification(&mut self, notification: Notification) {
        self.notifications.push(notification);
    }

    /// Drains requests from the mailbox.
    fn drain_requests(&mut self) -> Vec<(Action, AfterRequestCompleted)> {
        let mut requests = RefCell::new(Vec::default());
        std::mem::swap(&mut requests, &mut self.requests);
        requests.into_inner()
    }

    // TODO: currently blockchain doesn't read notifications, because services started
    // on start of the node aren't added into notifications list.
    // This should be fixed and notifications mechanism should be used instead of
    // `dispatcher.notify_api_changes`.
    #[allow(dead_code)]
    /// Consumes a mailbox, receiving the notifications about performed actions.
    pub fn get_notifications(self) -> Vec<Notification> {
        self.notifications
    }
}

/// Internal notification for blockchain core about actions happened during the
/// mailbox processing.
#[derive(Debug, Clone)]
pub enum Notification {
    /// Notification about adding a deployed artifact into some runtime.
    ArtifactDeployed { artifact: ArtifactId },
    /// Notification about instance added into some runtime.
    InstanceStarted {
        instance: InstanceSpec,
        part_of_core_api: bool,
    },
}

/// Enum denoting a request to perform a change in the Exonum blockchain structure.
#[derive(Debug, Clone)]
pub enum Action {
    /// Request to start artifact deployment process.
    StartDeploy { artifact: ArtifactId, spec: Vec<u8> },
    /// Request to register the deployed artifact in the blockchain.
    /// Make sure that you successfully complete the deploy artifact procedure.
    RegisterArtifact { artifact: ArtifactId, spec: Vec<u8> },
    /// Request to add a new service instance with the specified params.
    /// Make sure that the artifact is deployed.
    AddService {
        artifact: ArtifactId,
        instance_name: String,
        config: Vec<u8>,
    },
    /// Request to perform a configuration update with the specified changes.
    /// Make sure that no errors occur when applying these changes.
    UpdateConfig {
        caller_instance_id: InstanceId,
        changes: Vec<ConfigChange>,
    },
}
