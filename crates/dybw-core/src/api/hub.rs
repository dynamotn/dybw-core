//! Live updates from the Bitwarden notifications hub (SignalR over a WebSocket, MessagePack protocol), ported from the
//! plugin's `notifications.ts`. A notification is never trusted for content: it only says "something changed", and the
//! regular sync then fetches and verifies everything. A hostile or noisy server can therefore at most cause extra
//! syncs, which are coalesced and spaced out.
//!
//! [`Hub`] is sans-I/O: every call takes the current time and returns what the host must do ([`HubOut`]). [`run_hub`]
//! is the driver over the [`Events`] and [`Clock`] ports.

use super::msgpack::{Msg, decode_msgpack, split_signalr_frames};
use crate::ports::{Clock, EventSocket, Events, Frame};
use futures_util::future::{Either, select};
use serde_json::Value;
use std::pin::pin;

const RECORD_SEPARATOR: u8 = 0x1e;
const HANDSHAKE: &str = "{\"protocol\":\"messagepack\",\"version\":1}\u{1e}";
/// A SignalR ping message (`[6]`) with its length prefix.
const PING: [u8; 3] = [0x02, 0x91, 0x06];
const MAX_MESSAGE: usize = 1 << 20;

/// Hub URL of a Bitwarden server, from its notifications base URL.
pub fn hub_url(notifications_base: &str, access_token: &str) -> String {
    let base = if let Some(rest) = notifications_base.strip_prefix("https:") {
        format!("wss:{rest}")
    } else if let Some(rest) = notifications_base.strip_prefix("http:") {
        format!("ws:{rest}")
    } else {
        notifications_base.to_owned()
    };
    let mut url = format!("{}/hub?access_token=", base.trim_end_matches('/'));
    for b in access_token.bytes() {
        // What encodeURIComponent leaves alone.
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            url.push(char::from(b));
        } else {
            url.push_str(&format!("%{b:02X}"));
        }
    }
    url
}

/// Timing of the hub. Defaults are the plugin's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubOptions {
    pub ping_interval_ms: u64,
    /// Reconnect when nothing at all arrived for this long.
    pub server_timeout_ms: u64,
    /// Wait for notifications to settle before reporting them.
    pub settle_ms: u64,
    /// Never report changes more often than this.
    pub min_interval_ms: u64,
    /// Delays before reconnect attempts; the last one repeats.
    pub backoff_ms: Vec<u64>,
    /// The delays start over only once a connection stayed up this long.
    pub stable_ms: u64,
}

impl Default for HubOptions {
    fn default() -> Self {
        Self {
            ping_interval_ms: 15_000,
            server_timeout_ms: 60_000,
            settle_ms: 1_000,
            min_interval_ms: 5_000,
            backoff_ms: vec![2_000, 5_000, 15_000, 60_000, 300_000],
            stable_ms: 30_000,
        }
    }
}

/// What the host must do after a call. Every call ends with the `WakeAt` of its earliest deadline, if it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubOut {
    Send(Frame),
    /// Close the socket (the hub dropped the connection and already scheduled the `Reconnect`).
    Close,
    /// The vault changed elsewhere: sync.
    Changed,
    Connected(bool),
    /// Open a new connection at this time.
    Reconnect {
        at_ms: i64,
    },
    /// Call [`Hub::on_tick`] at this time.
    WakeAt(i64),
}

/// The connection state machine. Not tied to a socket: the host reports opens, frames, closes and ticks.
#[derive(Debug)]
pub struct Hub {
    options: HubOptions,
    own_device_id: String,
    handshaken: bool,
    attempt: usize,
    idle_at: Option<i64>,
    ping_at: Option<i64>,
    stable_at: Option<i64>,
    settle_at: Option<i64>,
    last_change: Option<i64>,
}

/// A message that makes the hub start over.
struct Bad;

fn ms(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn due(at: Option<i64>, now: i64) -> bool {
    at.is_some_and(|t| t <= now)
}

impl Hub {
    pub fn new(options: HubOptions, own_device_id: String) -> Self {
        Self {
            options,
            own_device_id,
            handshaken: false,
            attempt: 0,
            idle_at: None,
            ping_at: None,
            stable_at: None,
            settle_at: None,
            last_change: None,
        }
    }

    /// The socket opened: negotiate the protocol.
    pub fn on_open(&mut self, now: i64) -> Vec<HubOut> {
        self.handshaken = false;
        self.touch(now);
        self.finish(vec![HubOut::Send(Frame::Text(HANDSHAKE.into()))])
    }

    pub fn on_frame(&mut self, frame: Frame, now: i64) -> Vec<HubOut> {
        let mut out = Vec::new();
        self.touch(now);
        let result = match &frame {
            Frame::Text(_) if self.handshaken => Ok(()), // Only the MessagePack protocol was negotiated.
            Frame::Text(t) => self.receive(t.as_bytes(), now, &mut out),
            Frame::Binary(b) => self.receive(b, now, &mut out),
        };
        if result.is_err() {
            out.push(HubOut::Close);
            self.teardown(now, &mut out);
        }
        self.finish(out)
    }

    /// The transport ended (closed, failed, or never came up): schedule the next attempt.
    pub fn on_close(&mut self, now: i64) -> Vec<HubOut> {
        let mut out = Vec::new();
        self.teardown(now, &mut out);
        self.finish(out)
    }

    /// A deadline from `WakeAt` came.
    pub fn on_tick(&mut self, now: i64) -> Vec<HubOut> {
        let mut out = Vec::new();
        if due(self.stable_at, now) {
            self.stable_at = None;
            self.attempt = 0;
        }
        if due(self.idle_at, now) {
            out.push(HubOut::Close);
            self.teardown(now, &mut out);
        }
        if due(self.ping_at, now) {
            self.ping_at = Some(now.saturating_add(ms(self.options.ping_interval_ms)));
            out.push(HubOut::Send(Frame::Binary(PING.to_vec())));
        }
        if due(self.settle_at, now) {
            self.settle_at = None;
            self.last_change = Some(now);
            out.push(HubOut::Changed);
        }
        self.finish(out)
    }

    fn finish(&self, mut out: Vec<HubOut>) -> Vec<HubOut> {
        let next = [self.idle_at, self.ping_at, self.stable_at, self.settle_at].into_iter().flatten().min();
        out.extend(next.map(HubOut::WakeAt));
        out
    }

    /// Something arrived: the connection is alive.
    fn touch(&mut self, now: i64) {
        self.idle_at = Some(now.saturating_add(ms(self.options.server_timeout_ms)));
    }

    fn receive(&mut self, bytes: &[u8], now: i64, out: &mut Vec<HubOut>) -> Result<(), Bad> {
        let mut rest = bytes;
        if !self.handshaken {
            let end = bytes.iter().position(|b| *b == RECORD_SEPARATOR).ok_or(Bad)?;
            let (head, tail) = bytes.split_at(end);
            let reply: Value = serde_json::from_slice(head).map_err(|_| Bad)?;
            // shortcut: any `error` that is not null or false refuses, the plugin lets "" and 0 through; stricter.
            if matches!(reply.as_object().ok_or(Bad)?.get("error"), Some(e) if !matches!(e, Value::Null | Value::Bool(false)))
            {
                return Err(Bad);
            }
            self.handshaken = true;
            // Not yet stable: a server that accepts the handshake and then closes would get a reconnect every 2 s.
            self.stable_at = Some(now.saturating_add(ms(self.options.stable_ms)));
            self.ping_at = Some(now.saturating_add(ms(self.options.ping_interval_ms)));
            out.push(HubOut::Connected(true));
            rest = tail.get(1..).unwrap_or_default();
        }
        for frame in split_signalr_frames(rest, MAX_MESSAGE).map_err(|_| Bad)? {
            self.handle_message(&decode_msgpack(frame).map_err(|_| Bad)?, now)?;
        }
        Ok(())
    }

    fn handle_message(&mut self, message: &Msg, now: i64) -> Result<(), Bad> {
        let Msg::Array(items) = message else { return Ok(()) };
        match items.first() {
            Some(Msg::Int(7)) => return Err(Bad), // Close
            Some(Msg::Int(1)) => {}               // Invocation
            _ => return Ok(()),
        }
        if !matches!(items.get(3), Some(Msg::Str(target)) if target == "ReceiveMessage") {
            return Ok(());
        }
        let Some(Msg::Array(args)) = items.get(4) else { return Ok(()) };
        let Some(Msg::Map(notification)) = args.first() else { return Ok(()) };
        let field = |name: &str| notification.iter().find(|(k, _)| k == name).map(|(_, v)| v);
        // The plugin's push types: SyncCipherUpdate (0) to SyncCipherDelete (9).
        if !matches!(field("Type"), Some(Msg::Int(0..=9))) {
            return Ok(());
        }
        if matches!(field("ContextId"), Some(Msg::Str(id)) if *id == self.own_device_id) {
            return Ok(());
        }
        self.note_change(now);
        Ok(())
    }

    /// Coalesces a burst of notifications into one report, spaced at least `min_interval_ms` apart.
    fn note_change(&mut self, now: i64) {
        let settled = now.saturating_add(ms(self.options.settle_ms));
        let spaced = self.last_change.map_or(i64::MIN, |t| t.saturating_add(ms(self.options.min_interval_ms)));
        self.settle_at = Some(settled.max(spaced));
    }

    /// Ends the connection and schedules the next attempt.
    fn teardown(&mut self, now: i64, out: &mut Vec<HubOut>) {
        if self.handshaken {
            self.handshaken = false;
            out.push(HubOut::Connected(false));
        }
        self.idle_at = None;
        self.ping_at = None;
        self.stable_at = None;
        let delays = &self.options.backoff_ms;
        let delay = delays.get(self.attempt.min(delays.len().saturating_sub(1))).copied().unwrap_or(0).max(1); // at least 1 ms, so an empty list is no busy loop
        self.attempt = self.attempt.saturating_add(1);
        out.push(HubOut::Reconnect { at_ms: now.saturating_add(ms(delay)) });
    }
}

/// What the driver keeps from the hub's outputs.
#[derive(Default)]
struct Pump {
    wake: Option<i64>,
    reconnect_at: i64,
    close: bool,
}

impl Pump {
    /// Acts on everything but sends, which the caller does.
    fn absorb(&mut self, outs: Vec<HubOut>, on_change: &mut impl FnMut()) -> Vec<Frame> {
        self.wake = None;
        let mut sends = Vec::new();
        for o in outs {
            match o {
                HubOut::Send(f) => sends.push(f),
                HubOut::Close => self.close = true,
                HubOut::Changed => on_change(),
                HubOut::Connected(_) => {}
                HubOut::Reconnect { at_ms } => self.reconnect_at = at_ms,
                HubOut::WakeAt(t) => self.wake = Some(t),
            }
        }
        sends
    }
}

/// One connection, from its open to its end. The hub has scheduled the next attempt when this returns.
async fn session<S: EventSocket, C: Clock>(
    socket: &mut S,
    clock: &C,
    hub: &mut Hub,
    on_change: &mut impl FnMut(),
    stop: &impl Fn() -> bool,
    pump: &mut Pump,
) {
    pump.close = false;
    let mut sends = pump.absorb(hub.on_open(clock.now_ms()), on_change);
    loop {
        let mut failed = false;
        for frame in sends {
            failed |= socket.send(frame).await.is_err();
        }
        if pump.close {
            return;
        }
        if failed || stop() {
            pump.absorb(hub.on_close(clock.now_ms()), on_change);
            return;
        }
        let now = clock.now_ms();
        // Frames can arrive back to back and recv is polled first, so a due deadline is served before waiting.
        if pump.wake.is_some_and(|t| t <= now) {
            sends = pump.absorb(hub.on_tick(now), on_change);
            continue;
        }
        // A live connection always has a deadline (the idle timeout); the cap only keeps the sleep finite.
        let wait = pump.wake.map_or(u64::from(u32::MAX), |t| t.saturating_sub(now).unsigned_abs());
        let event = {
            let recv = pin!(socket.recv());
            let timer = pin!(clock.sleep_ms(wait));
            match select(recv, timer).await {
                Either::Left((received, _)) => Some(received),
                Either::Right(_) => None,
            }
        };
        let now = clock.now_ms();
        sends = match event {
            Some(Some(Ok(frame))) => pump.absorb(hub.on_frame(frame, now), on_change),
            Some(Some(Err(_)) | None) => {
                pump.absorb(hub.on_close(now), on_change);
                return;
            }
            None => pump.absorb(hub.on_tick(now), on_change),
        };
    }
}

/// Keeps one connection to the hub up until `stop` says otherwise, calling `on_change` when the vault changed
/// elsewhere. `url` is asked for a fresh URL (with a current access token) before every attempt; `None` counts as a
/// failed attempt. `stop` is checked between steps; the host cancels a wait by dropping the future.
pub async fn run_hub<E: Events, C: Clock>(
    events: &E,
    clock: &C,
    url: impl AsyncFn() -> Option<String>,
    hub: &mut Hub,
    mut on_change: impl FnMut(),
    stop: impl Fn() -> bool,
) {
    let mut pump = Pump { reconnect_at: clock.now_ms(), ..Pump::default() };
    loop {
        // Until the next attempt, still serve the hub's own deadline: a change noted before the drop is reported
        // after its settle time, not after the (possibly 5 minute) backoff.
        loop {
            if stop() {
                return;
            }
            let now = clock.now_ms();
            if now >= pump.reconnect_at {
                break;
            }
            let until = pump.wake.map_or(pump.reconnect_at, |t| t.min(pump.reconnect_at));
            clock.sleep_ms(until.saturating_sub(now).unsigned_abs()).await;
            let now = clock.now_ms();
            if pump.wake.is_some_and(|t| t <= now) {
                pump.absorb(hub.on_tick(now), &mut on_change);
            }
        }
        let socket = match url().await {
            Some(u) => events.connect(&u).await.ok(),
            None => None,
        };
        let Some(mut socket) = socket else {
            pump.absorb(hub.on_close(clock.now_ms()), &mut on_change);
            continue;
        };
        session(&mut socket, clock, hub, &mut on_change, &stop, &mut pump).await;
        socket.close().await;
    }
}
