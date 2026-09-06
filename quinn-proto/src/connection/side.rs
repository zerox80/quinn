use std::sync::Arc;

use bytes::Bytes;

use crate::{Side, TokenStore, config::ServerConfig, shared::ConnectionId};

/// Fields of `Connection` specific to it being client-side or server-side
pub(super) enum ConnectionSide {
    Client {
        /// Sent in every outgoing Initial packet. Always empty after Initial keys are discarded
        token: Bytes,
        token_store: Arc<dyn TokenStore>,
        server_name: String,
    },
    Server {
        server_config: Arc<ServerConfig>,
    },
}

impl ConnectionSide {
    pub(super) fn remote_may_migrate(&self) -> bool {
        match self {
            Self::Server { server_config } => server_config.migration,
            Self::Client { .. } => false,
        }
    }

    pub(super) fn is_client(&self) -> bool {
        self.side().is_client()
    }

    pub(super) fn is_server(&self) -> bool {
        self.side().is_server()
    }

    pub(super) fn side(&self) -> Side {
        match *self {
            Self::Client { .. } => Side::Client,
            Self::Server { .. } => Side::Server,
        }
    }
}

impl From<SideArgs> for ConnectionSide {
    fn from(side: SideArgs) -> Self {
        match side {
            SideArgs::Client {
                token_store,
                server_name,
            } => Self::Client {
                token: token_store.take(&server_name).unwrap_or_default(),
                token_store,
                server_name,
            },
            SideArgs::Server {
                server_config,
                pref_addr_cid: _,
                path_validated: _,
            } => Self::Server { server_config },
        }
    }
}

/// Parameters to `Connection::new` specific to it being client-side or server-side
pub(crate) enum SideArgs {
    Client {
        token_store: Arc<dyn TokenStore>,
        server_name: String,
    },
    Server {
        server_config: Arc<ServerConfig>,
        pref_addr_cid: Option<ConnectionId>,
        path_validated: bool,
    },
}

impl SideArgs {
    pub(crate) fn pref_addr_cid(&self) -> Option<ConnectionId> {
        match *self {
            Self::Client { .. } => None,
            Self::Server { pref_addr_cid, .. } => pref_addr_cid,
        }
    }

    pub(crate) fn path_validated(&self) -> bool {
        match *self {
            Self::Client { .. } => true,
            Self::Server { path_validated, .. } => path_validated,
        }
    }

    pub(crate) fn side(&self) -> Side {
        match *self {
            Self::Client { .. } => Side::Client,
            Self::Server { .. } => Side::Server,
        }
    }
}
