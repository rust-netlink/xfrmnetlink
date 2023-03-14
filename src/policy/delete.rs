// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;
use std::net::IpAddr;

use crate::{try_nl, Error, Handle};
use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_xfrm::{
    policy::DelGetMessage, Mark, SecurityCtx, UserPolicyType, XfrmAttrs, XfrmMessage,
};

/// A request to delete xfrm policies. This is equivalent to the `ip xfrm policy delete` command.
#[non_exhaustive]
pub struct PolicyDeleteRequest {
    handle: Handle,
    message: DelGetMessage,
}

impl PolicyDeleteRequest {
    pub(crate) fn new(
        handle: Handle,
        src_addr: IpAddr,
        src_prefix_len: u8,
        dst_addr: IpAddr,
        dst_prefix_len: u8,
    ) -> Self {
        let mut message = DelGetMessage::default();

        message
            .user_policy_id
            .selector
            .source_prefix(&src_addr, src_prefix_len);
        message
            .user_policy_id
            .selector
            .destination_prefix(&dst_addr, dst_prefix_len);

        PolicyDeleteRequest { handle, message }
    }

    pub(crate) fn new_index(handle: Handle, index: u32) -> Self {
        let mut message = DelGetMessage::default();

        message.user_policy_id.index = index;

        PolicyDeleteRequest { handle, message }
    }

    pub fn direction(mut self, direction: u8) -> Self {
        self.message.user_policy_id.direction = direction;
        self
    }

    pub fn ptype(mut self, ptype: u8) -> Self {
        self.message
            .nlas
            .push(XfrmAttrs::PolicyType(UserPolicyType {
                ptype,
                ..Default::default()
            }));
        self
    }
    pub fn security_context(mut self, secctx: &[u8]) -> Self {
        let mut sc = SecurityCtx::default();

        sc.context(secctx);
        self.message.nlas.push(XfrmAttrs::SecurityContext(sc));
        self
    }

    /// Manually change the policy index instead of letting the kernel choose one.
    /// Only certain values will work, and it depends on the direction.
    /// The kernel does a bitwise 'and' on the index with 7, and compares it with
    /// the direction ((index & 7) == dir). For example:
    ///   XFRM_POLICY_IN  (0) -- valid indexes are: 8, 16, 24, 32, 40...
    ///   XFRM_POLICY_OUT (1) -- valid indexes are: 1, 9, 17, 25, 33...
    ///   XFRM_POLICY_FWD (2) -- valid indexes are: 2, 10, 18, 26, 34...
    /// If this pattern is not followed, the kernel will return -EINVAL (Invalid argument).
    pub fn index(mut self, index: u32) -> Self {
        self.message.user_policy_id.index = index;
        self
    }
    pub fn ifid(mut self, ifid: u32) -> Self {
        self.message.nlas.push(XfrmAttrs::IfId(ifid));
        self
    }
    pub fn mark(mut self, mark: u32, mask: u32) -> Self {
        self.message
            .nlas
            .push(XfrmAttrs::Mark(Mark { value: mark, mask }));
        self
    }

    pub fn selector_protocol(mut self, proto: u8) -> Self {
        self.message.user_policy_id.selector.proto = proto;
        self
    }
    pub fn selector_protocol_src_port(mut self, port: u16) -> Self {
        self.message.user_policy_id.selector.sport = port;
        self.message.user_policy_id.selector.sport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_dst_port(mut self, port: u16) -> Self {
        self.message.user_policy_id.selector.dport = port;
        self.message.user_policy_id.selector.dport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_type(mut self, proto_type: u8) -> Self {
        self.message.user_policy_id.selector.sport = proto_type as u16;
        self.message.user_policy_id.selector.sport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_code(mut self, proto_code: u8) -> Self {
        self.message.user_policy_id.selector.dport = proto_code as u16;
        self.message.user_policy_id.selector.dport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_gre_key(mut self, gre_key: u32) -> Self {
        self.message.user_policy_id.selector.sport = (gre_key >> 16) as u16;
        self.message.user_policy_id.selector.sport_mask = u16::MAX;
        self.message.user_policy_id.selector.dport = (gre_key & 0xffff) as u16;
        self.message.user_policy_id.selector.dport_mask = u16::MAX;
        self
    }
    pub fn selector_dev_id(mut self, id: u32) -> Self {
        self.message.user_policy_id.selector.ifindex = id as i32;
        self
    }

    /// Execute the request.
    pub async fn execute(self) -> Result<(), Error> {
        let PolicyDeleteRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::DeletePolicy(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = handle.request(req)?;

        while let Some(message) = response.next().await {
            try_nl!(message);
        }
        Ok(())
    }

    /// Execute the request without waiting for an ACK response.
    pub fn execute_noack(self) -> Result<(), Error> {
        let PolicyDeleteRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::DeletePolicy(message));
        req.header.flags = NLM_F_REQUEST;

        let mut _response = handle.request(req)?;

        Ok(())
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut DelGetMessage {
        &mut self.message
    }
}
