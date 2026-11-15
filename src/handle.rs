// SPDX-License-Identifier: MIT

use futures::{Stream, StreamExt};

use crate::{Error, PolicyHandle, StateHandle};
use netlink_packet_core::NetlinkMessage;
use netlink_packet_xfrm::XfrmMessage;
use netlink_proto::{sys::SocketAddr, ConnectionHandle};

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Handle(ConnectionHandle<XfrmMessage>);

impl Handle {
    pub(crate) fn new(conn: ConnectionHandle<XfrmMessage>) -> Self {
        Handle(conn)
    }

    pub fn request(
        &mut self,
        message: NetlinkMessage<XfrmMessage>,
    ) -> Result<impl Stream<Item = Result<NetlinkMessage<XfrmMessage>, Error>>, Error> {
        let stream = self
            .0
            .request(message, SocketAddr::new(0, 0))
            .map_err(|_| Error::RequestFailed)?;
        Ok(stream.map(|result| result.map_err(|err| Error::NetlinkProtoError(err.to_string()))))
    }

    pub fn notify(&mut self, msg: NetlinkMessage<XfrmMessage>) -> Result<(), Error> {
        self.0
            .notify(msg, SocketAddr::new(0, 0))
            .map_err(|_| Error::RequestFailed)?;
        Ok(())
    }

    /// Create a new handle, specifically for policy requests (equivalent to `ip xfrm policy` commands)
    pub fn policy(&self) -> PolicyHandle {
        PolicyHandle::new(self.clone())
    }

    /// Create a new handle, specifically for state requests (equivalent to `ip xfrm state` commands)
    pub fn state(&self) -> StateHandle {
        StateHandle::new(self.clone())
    }
}
