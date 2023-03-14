// SPDX-License-Identifier: MIT

use futures::{
    future::{self, Either},
    stream::{StreamExt, TryStream},
    FutureExt,
};
use std::net::IpAddr;

use crate::{try_xfrmnl, Error, Handle};
use netlink_packet_core::{NetlinkMessage, NLM_F_REQUEST};
use netlink_packet_xfrm::{
    state::{AllocSpiMessage, ModifyMessage},
    Mark, XfrmAttrs, XfrmMessage,
};

/// A request to allocate a SPI for an xfrm state. This is equivalent to the `ip xfrm state allocspi` command.
#[non_exhaustive]
pub struct StateAllocSpiRequest {
    handle: Handle,
    message: AllocSpiMessage,
}

impl StateAllocSpiRequest {
    pub(crate) fn new(handle: Handle, src_addr: IpAddr, dst_addr: IpAddr) -> Self {
        let mut message = AllocSpiMessage::default();

        message.spi_info.info.source(&src_addr);
        message.spi_info.info.destination(&dst_addr);
        message.spi_info.info.id.spi = 0;

        StateAllocSpiRequest { handle, message }
    }

    pub fn protocol(mut self, protocol: u8) -> Self {
        self.message.spi_info.protocol(protocol);
        self
    }
    pub fn spi_range(mut self, spi_min: u32, spi_max: u32) -> Self {
        self.message.spi_info.spi_range(spi_min, spi_max);
        self
    }
    pub fn mode(mut self, mode: u8) -> Self {
        self.message.spi_info.info.mode = mode;
        self
    }
    pub fn mark(mut self, mark: u32, mask: u32) -> Self {
        self.message
            .nlas
            .push(XfrmAttrs::Mark(Mark { value: mark, mask }));
        self
    }
    pub fn reqid(mut self, reqid: u32) -> Self {
        self.message.spi_info.info.reqid = reqid;
        self
    }
    // Not sure how the kernel is using this, seems to always come back as 0.
    pub fn seq(mut self, seq: u32) -> Self {
        self.message.spi_info.info.seq = seq;
        self
    }
    // Not in iproute2, but kernel allows it
    pub fn ifid(mut self, ifid: u32) -> Self {
        self.message.nlas.push(XfrmAttrs::IfId(ifid));
        self
    }

    /// Execute the request
    pub fn execute(self) -> impl TryStream<Ok = ModifyMessage, Error = Error> {
        let StateAllocSpiRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(XfrmMessage::AllocSpi(message));
        req.header.flags = NLM_F_REQUEST;

        // A successful alloc spi request returns with an Add/ModifyMessage response.
        match handle.request(req) {
            Ok(response) => {
                Either::Left(response.map(move |msg| Ok(try_xfrmnl!(msg, XfrmMessage::AddSa))))
            }
            Err(e) => Either::Right(future::err::<ModifyMessage, Error>(e).into_stream()),
        }
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut AllocSpiMessage {
        &mut self.message
    }
}
