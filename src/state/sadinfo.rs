// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;

use crate::{try_xfrmnl, Error, Handle};
use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_xfrm::{
    state::{GetSadInfoMessage, NewSadInfoMessage},
    XfrmMessage,
};

/// A request to get xfrm state statistics. This is equivalent to the `ip xfrm state count` command.
#[non_exhaustive]
pub struct StateGetSadInfoRequest {
    handle: Handle,
    message: GetSadInfoMessage,
}

impl StateGetSadInfoRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        let message = GetSadInfoMessage { flags: u32::MAX };

        StateGetSadInfoRequest { handle, message }
    }

    /// Execute the request
    pub async fn execute(self) -> Result<NewSadInfoMessage, Error> {
        let StateGetSadInfoRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::GetSadInfo(message));

        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = handle.request(req)?;

        if let Some(msg) = response.next().await {
            return Ok(try_xfrmnl!(msg, XfrmMessage::NewSadInfo));
        }
        Err(Error::RequestFailed)
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut GetSadInfoMessage {
        &mut self.message
    }
}
