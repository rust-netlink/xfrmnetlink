// SPDX-License-Identifier: MIT

use std::io;

use futures::channel::mpsc::UnboundedReceiver;

use crate::Handle;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_xfrm::XfrmMessage;
use netlink_proto::sys::{AsyncSocket, SocketAddr};
use netlink_proto::Connection;

const NETLINK_XFRM: isize = libc::NETLINK_XFRM as isize;

#[cfg(feature = "tokio_socket")]
#[allow(clippy::type_complexity)]
pub fn new_connection() -> io::Result<(
    Connection<XfrmMessage>,
    Handle,
    UnboundedReceiver<(NetlinkMessage<XfrmMessage>, SocketAddr)>,
)> {
    new_connection_with_socket()
}

#[allow(clippy::type_complexity)]
pub fn new_connection_with_socket<S>() -> io::Result<(
    Connection<XfrmMessage, S>,
    Handle,
    UnboundedReceiver<(NetlinkMessage<XfrmMessage>, SocketAddr)>,
)>
where
    S: AsyncSocket,
{
    let (conn, handle, messages) =
        netlink_proto::new_connection_with_socket::<XfrmMessage, S>(NETLINK_XFRM)
            .map_err(io::Error::other)?;
    Ok((conn, Handle::new(handle), messages))
}
