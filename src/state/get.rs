// SPDX-License-Identifier: MIT

use futures::{
    future::{self, Either},
    stream::{StreamExt, TryStream},
    FutureExt,
};
use std::net::IpAddr;

use crate::{try_xfrmnl, Error, Handle};
use netlink_packet_core::{NetlinkMessage, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_xfrm::{
    state::{DelGetMessage, GetDumpMessage, ModifyMessage},
    Address, AddressFilter, Mark, XfrmAttrs, XfrmMessage,
};

/// A request to get xfrm state. This is equivalent to the `ip xfrm state get` command.
#[non_exhaustive]
pub struct StateGetRequest {
    handle: Handle,
    message: DelGetMessage,
}

impl StateGetRequest {
    pub(crate) fn new(handle: Handle, src_addr: IpAddr, dst_addr: IpAddr) -> Self {
        let mut message = DelGetMessage::default();

        message
            .nlas
            .push(XfrmAttrs::SrcAddr(Address::from_ip(&src_addr)));

        message.user_sa_id.destination(&dst_addr);

        StateGetRequest { handle, message }
    }

    pub fn protocol(mut self, protocol: u8) -> Self {
        self.message.user_sa_id.proto = protocol;
        self
    }
    pub fn spi(mut self, spi: u32) -> Self {
        self.message.user_sa_id.spi = spi;
        self
    }

    // Delete and Get won't work to find/retrieve the state in the kernel
    // if mask is set incorrectly during the state Add. i.e. if the mask
    // is set in such a way that it doesn't cover the mark, a full flush
    // may be needed to delete it.
    pub fn mark(mut self, mark: u32, mask: u32) -> Self {
        self.message
            .nlas
            .push(XfrmAttrs::Mark(Mark { value: mark, mask }));
        self
    }

    /// Execute the request
    pub fn execute(self) -> impl TryStream<Ok = ModifyMessage, Error = Error> {
        let StateGetRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::GetSa(message));
        req.header.flags = NLM_F_REQUEST;

        // A successful policy Get request returns with an Add/ModifyMessage response.
        match handle.request(req) {
            Ok(response) => {
                Either::Left(response.map(move |msg| Ok(try_xfrmnl!(msg, XfrmMessage::AddSa))))
            }
            Err(e) => Either::Right(future::err::<ModifyMessage, Error>(e).into_stream()),
        }
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut DelGetMessage {
        &mut self.message
    }
}

/// A request to dump xfrm states. This is equivalent to the `ip xfrm state list` command.
#[non_exhaustive]
pub struct StateGetDumpRequest {
    handle: Handle,
    message: GetDumpMessage,
}

impl StateGetDumpRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        let message = GetDumpMessage::default();

        StateGetDumpRequest { handle, message }
    }

    pub fn address_filter(
        mut self,
        src_addr: IpAddr,
        src_prefix_len: u8,
        dst_addr: IpAddr,
        dst_prefix_len: u8,
    ) -> Self {
        let mut addr_filter = AddressFilter::default();

        addr_filter.source_prefix(&src_addr, src_prefix_len);
        addr_filter.destination_prefix(&dst_addr, dst_prefix_len);

        self.message
            .nlas
            .push(XfrmAttrs::AddressFilter(addr_filter));
        self
    }

    /// Execute the request
    pub fn execute(self) -> impl TryStream<Ok = ModifyMessage, Error = Error> {
        let StateGetDumpRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::GetDumpSa(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        // A successful state Get with dump flag request returns with an Add/ModifyMessage response.
        match handle.request(req) {
            Ok(response) => {
                Either::Left(response.map(move |msg| Ok(try_xfrmnl!(msg, XfrmMessage::AddSa))))
            }
            Err(e) => Either::Right(future::err::<ModifyMessage, Error>(e).into_stream()),
        }
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut GetDumpMessage {
        &mut self.message
    }
}
