// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;
use std::net::IpAddr;

use crate::{try_nl, Error, Handle};
use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_xfrm::{
    policy::ModifyMessage, Mark, SecurityCtx, UserPolicyType, UserTemplate, XfrmAttrs, XfrmMessage,
};

/// A request to add or update xfrm policies. This is equivalent to the `ip xfrm policy add|update` commands.
#[non_exhaustive]
pub struct PolicyModifyRequest {
    handle: Handle,
    message: ModifyMessage,
    update: bool,
    templates: Vec<UserTemplate>,
}

impl PolicyModifyRequest {
    pub(crate) fn new(
        handle: Handle,
        update: bool,
        src_addr: IpAddr,
        src_prefix_len: u8,
        dst_addr: IpAddr,
        dst_prefix_len: u8,
    ) -> Self {
        let mut message = ModifyMessage::default();

        message
            .user_policy_info
            .selector
            .source_prefix(&src_addr, src_prefix_len);
        message
            .user_policy_info
            .selector
            .destination_prefix(&dst_addr, dst_prefix_len);

        PolicyModifyRequest {
            handle,
            message,
            update,
            templates: Vec::default(),
        }
    }

    pub fn direction(mut self, direction: u8) -> Self {
        self.message.user_policy_info.direction = direction;
        self
    }

    pub fn action(mut self, action: u8) -> Self {
        self.message.user_policy_info.action = action;
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
        self.message.user_policy_info.index = index;
        self
    }
    pub fn priority(mut self, priority: u32) -> Self {
        self.message.user_policy_info.priority = priority;
        self
    }
    pub fn ifid(mut self, ifid: u32) -> Self {
        self.message.nlas.push(XfrmAttrs::IfId(ifid));
        self
    }
    pub fn flags(mut self, flags: u8) -> Self {
        self.message.user_policy_info.flags = flags;
        self
    }
    pub fn mark(mut self, mark: u32, mask: u32) -> Self {
        self.message
            .nlas
            .push(XfrmAttrs::Mark(Mark { value: mark, mask }));
        self
    }
    pub fn time_limit(mut self, soft: u64, hard: u64) -> Self {
        self.message
            .user_policy_info
            .lifetime_cfg
            .soft_add_expires_seconds = soft;
        self.message
            .user_policy_info
            .lifetime_cfg
            .hard_add_expires_seconds = hard;
        self
    }
    pub fn time_use_limit(mut self, soft: u64, hard: u64) -> Self {
        self.message
            .user_policy_info
            .lifetime_cfg
            .soft_use_expires_seconds = soft;
        self.message
            .user_policy_info
            .lifetime_cfg
            .hard_use_expires_seconds = hard;
        self
    }
    pub fn byte_limit(mut self, soft: u64, hard: u64) -> Self {
        self.message.user_policy_info.lifetime_cfg.soft_byte_limit = soft;
        self.message.user_policy_info.lifetime_cfg.hard_byte_limit = hard;
        self
    }
    pub fn packet_limit(mut self, soft: u64, hard: u64) -> Self {
        self.message.user_policy_info.lifetime_cfg.soft_packet_limit = soft;
        self.message.user_policy_info.lifetime_cfg.hard_packet_limit = hard;
        self
    }

    pub fn selector_protocol(mut self, proto: u8) -> Self {
        self.message.user_policy_info.selector.proto = proto;
        self
    }
    pub fn selector_protocol_src_port(mut self, port: u16) -> Self {
        self.message.user_policy_info.selector.sport = port;
        self.message.user_policy_info.selector.sport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_dst_port(mut self, port: u16) -> Self {
        self.message.user_policy_info.selector.dport = port;
        self.message.user_policy_info.selector.dport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_type(mut self, proto_type: u8) -> Self {
        self.message.user_policy_info.selector.sport = proto_type as u16;
        self.message.user_policy_info.selector.sport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_code(mut self, proto_code: u8) -> Self {
        self.message.user_policy_info.selector.dport = proto_code as u16;
        self.message.user_policy_info.selector.dport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_gre_key(mut self, gre_key: u32) -> Self {
        self.message.user_policy_info.selector.sport = (gre_key >> 16) as u16;
        self.message.user_policy_info.selector.sport_mask = u16::MAX;
        self.message.user_policy_info.selector.dport = (gre_key & 0xffff) as u16;
        self.message.user_policy_info.selector.dport_mask = u16::MAX;
        self
    }
    pub fn selector_dev_id(mut self, id: u32) -> Self {
        self.message.user_policy_info.selector.ifindex = id as i32;
        self
    }

    // This adds to a temporary Vec instead of modifying the message
    // directly. When execute is called, all of the added templates
    // are grouped into one array and passed to the kernel as a
    // single XFRMA_TMPL attribute.
    pub fn add_template(mut self, template: UserTemplate) -> Self {
        self.templates.push(template);
        self
    }

    /// Execute the request.
    pub async fn execute(self) -> Result<(), Error> {
        let PolicyModifyRequest {
            mut handle,
            mut message,
            update,
            templates,
        } = self;

        if !templates.is_empty() {
            message.nlas.push(XfrmAttrs::Template(templates));
        }

        let mut req = if update {
            NetlinkMessage::from(XfrmMessage::UpdatePolicy(message))
        } else {
            NetlinkMessage::from(XfrmMessage::AddPolicy(message))
        };
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = handle.request(req)?;

        while let Some(message) = response.next().await {
            try_nl!(message);
        }
        Ok(())
    }

    /// Execute the request without waiting for an ACK response.
    pub fn execute_noack(self) -> Result<(), Error> {
        let PolicyModifyRequest {
            mut handle,
            mut message,
            update,
            templates,
        } = self;

        if !templates.is_empty() {
            message.nlas.push(XfrmAttrs::Template(templates));
        }

        let mut req = if update {
            NetlinkMessage::from(XfrmMessage::UpdatePolicy(message))
        } else {
            NetlinkMessage::from(XfrmMessage::AddPolicy(message))
        };
        req.header.flags = NLM_F_REQUEST;

        let mut _response = handle.request(req)?;

        Ok(())
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut ModifyMessage {
        &mut self.message
    }
}
