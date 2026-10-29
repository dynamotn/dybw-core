//! Ports `test/notifications.test.ts` of the plugin onto the sans-I/O hub: its fake timers become explicit `now`
//! values, its fake sockets become the frames and outputs below.

use super::{Hub, HubOptions, HubOut as O, hub_url, resolve_server_urls, run_hub};
use crate::ports::{Clock, EventSocket, Events, Frame, PortError};
use crate::testing::block_on;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

const HANDSHAKE: &str = "{\"protocol\":\"messagepack\",\"version\":1}\u{1e}";
const OTHER: &str = "other-device";

fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
}

fn bin(b: &[u8]) -> Frame {
    Frame::Binary(b.to_vec())
}

fn enc(s: &str) -> Vec<u8> {
    let mut v = vec![0xa0 | s.len() as u8];
    v.extend(s.bytes());
    v
}

/// A short MessagePack message with its SignalR length prefix.
fn framed(body: &[u8]) -> Vec<u8> {
    let mut v = vec![body.len() as u8];
    v.extend(body);
    v
}

fn receive_message() -> Vec<u8> {
    [&[0x95, 0x01, 0x80, 0xc0][..], &enc("ReceiveMessage")].concat()
}

/// A `ReceiveMessage` invocation the way the server frames it.
fn invocation(ty: u8, context: Option<&str>) -> Vec<u8> {
    let ctx = context.map_or(vec![0xc0], |c| [&[0xd9, c.len() as u8][..], c.as_bytes()].concat());
    let body =
        [&receive_message()[..], &[0x91, 0x83], &enc("ContextId"), &ctx, &enc("Type"), &[ty], &enc("Payload"), &[0x80]]
            .concat();
    framed(&body)
}

fn hub() -> Hub {
    Hub::new(HubOptions::default(), "this-device".into())
}

/// Without the `WakeAt` that every call reports.
fn strip(outs: Vec<O>) -> Vec<O> {
    outs.into_iter().filter(|o| !matches!(o, O::WakeAt(_))).collect()
}

/// Opens the socket and completes the handshake at `now`.
fn up(h: &mut Hub, now: i64) {
    h.on_open(now);
    assert_eq!(strip(h.on_frame(bin(&[0x7b, 0x7d, 0x1e]), now)), [O::Connected(true)]);
}

#[test]
fn hub_urls() {
    for (server, expected) in [
        ("https://vault.bitwarden.com", "wss://notifications.bitwarden.com/hub?access_token=t%2Bk"),
        ("https://vault.bitwarden.eu", "wss://notifications.bitwarden.eu/hub?access_token=t%2Bk"),
        ("https://vault.example.com/bw/", "wss://vault.example.com/bw/notifications/hub?access_token=t%2Bk"),
        ("http://localhost:8080", "ws://localhost:8080/notifications/hub?access_token=t%2Bk"),
    ] {
        assert_eq!(hub_url(&resolve_server_urls(server).unwrap().notifications, "t+k"), expected, "{server}");
    }
    assert_eq!(hub_url("wss://x", "t"), "wss://x/hub?access_token=t", "a base that is already a socket URL");
    // encodeURIComponent keeps A-Z a-z 0-9 - _ . ! ~ * ' ( ) and escapes the rest as UTF-8.
    assert_eq!(hub_url("https://x///", "a b-_.!~*'()é"), "wss://x/hub?access_token=a%20b-_.!~*'()%C3%A9");
}

#[test]
fn default_options_are_the_plugins() {
    let o = HubOptions::default();
    assert_eq!(
        (o.ping_interval_ms, o.server_timeout_ms, o.settle_ms, o.min_interval_ms, o.stable_ms),
        (15_000, 60_000, 1_000, 5_000, 30_000)
    );
    assert_eq!(o.backoff_ms, [2_000, 5_000, 15_000, 60_000, 300_000]);
}

#[test]
fn negotiates_messagepack_then_reports_a_change_made_elsewhere() {
    let mut h = hub();
    assert_eq!(h.on_open(0), [O::Send(Frame::Text(HANDSHAKE.into())), O::WakeAt(60_000)]);
    assert_eq!(h.on_frame(bin(&[0x7b, 0x7d, 0x1e]), 0), [O::Connected(true), O::WakeAt(15_000)]);
    assert_eq!(h.on_frame(bin(&invocation(1, Some(OTHER))), 0), [O::WakeAt(1_000)]);
    assert_eq!(h.on_tick(999), [O::WakeAt(1_000)]);
    assert_eq!(h.on_tick(1_000), [O::Changed, O::WakeAt(15_000)]);
}

#[test]
fn understands_the_frame_vaultwarden_actually_sends() {
    let mut h = hub();
    up(&mut h, 0);
    let bytes = hex("c1 01 95 01 80 c0 ae 52 65 63 65 69 76 65 4d 65 73 73 61 67 65 91 83 a9 43 6f 6e 74 65 78 74 49
        64 d9 24 36 37 38 33 30 64 30 33 2d 63 66 61 32 2d 34 31 61 33 2d 39 34 31 66 2d 61 38 35 31 36 30 65 66 33
        39 65 38 a4 54 79 70 65 07 a7 50 61 79 6c 6f 61 64 83 a2 49 64 d9 24 61 31 36 31 34 32 39 34 2d 37 30 63 66
        2d 34 37 33 63 2d 39 35 35 64 2d 63 32 63 30 36 61 38 31 62 64 31 33 a6 55 73 65 72 49 64 d9 24 36 32 64 35
        39 62 64 30 2d 62 66 36 36 2d 34 37 30 66 2d 61 63 35 62 2d 65 37 62 31 31 63 32 62 32 30 31 62 ac 52 65 76
        69 73 69 6f 6e 44 61 74 65 d7 ff 82 f3 ea 18 6a da cf 93");
    assert_eq!(h.on_frame(bin(&bytes), 0), [O::WakeAt(1_000)]);
    assert_eq!(h.on_tick(1_000), [O::Changed, O::WakeAt(15_000)]);
}

#[test]
fn accepts_the_handshake_and_a_first_message_in_one_frame() {
    let mut h = hub();
    h.on_open(0);
    let both = [&[0x7b, 0x7d, 0x1e][..], &invocation(0, Some(OTHER))].concat();
    assert_eq!(h.on_frame(bin(&both), 0), [O::Connected(true), O::WakeAt(1_000)]);
    assert_eq!(h.on_tick(1_000), [O::Changed, O::WakeAt(15_000)]);
}

#[test]
fn ignores_changes_this_device_made_itself_and_other_push_types() {
    let mut h = hub();
    up(&mut h, 0);
    // LogOut (11), SyncSendCreate (12) and one past the plugin's set (10), then our own change.
    for (ty, ctx) in [(0, "this-device"), (11, OTHER), (12, OTHER), (10, OTHER)] {
        assert_eq!(strip(h.on_frame(bin(&invocation(ty, Some(ctx))), 0)), []);
    }
    assert_eq!(strip(h.on_tick(10_000)), []);
}

#[test]
fn every_vault_push_type_counts_and_a_nil_context_id_is_not_ours() {
    for ty in 0..=9 {
        let mut h = hub();
        up(&mut h, 0);
        h.on_frame(bin(&invocation(ty, None)), 0);
        assert_eq!(strip(h.on_tick(1_000)), [O::Changed], "type {ty}");
    }
}

#[test]
fn coalesces_a_burst_and_spaces_reports_out() {
    let mut h = hub();
    up(&mut h, 0);
    for _ in 0..50 {
        assert_eq!(h.on_frame(bin(&invocation(0, Some(OTHER))), 0), [O::WakeAt(1_000)]);
    }
    assert_eq!(h.on_tick(1_000), [O::Changed, O::WakeAt(15_000)]);
    assert_eq!(h.on_frame(bin(&invocation(0, Some(OTHER))), 1_000), [O::WakeAt(6_000)]);
    assert_eq!(h.on_tick(2_000), [O::WakeAt(6_000)]);
    assert_eq!(h.on_tick(6_000), [O::Changed, O::WakeAt(15_000)]);
}

#[test]
fn sends_pings_while_connected() {
    let mut h = hub();
    up(&mut h, 0);
    for k in 1..=3 {
        assert_eq!(h.on_tick(15_000 * k), [O::Send(bin(&[0x02, 0x91, 0x06])), O::WakeAt(15_000 * (k + 1))]);
    }
}

#[test]
fn reconnects_with_growing_delays_after_the_connection_drops() {
    let mut h = hub();
    up(&mut h, 0);
    assert_eq!(h.on_close(0), [O::Connected(false), O::Reconnect { at_ms: 2_000 }]);
    h.on_open(2_000);
    assert_eq!(h.on_close(2_000), [O::Reconnect { at_ms: 7_000 }]);
    // A connection that stayed up resets the delays.
    up(&mut h, 7_000);
    h.on_tick(37_000);
    assert_eq!(h.on_close(37_000), [O::Connected(false), O::Reconnect { at_ms: 39_000 }]);
}

#[test]
fn keeps_backing_off_from_a_server_that_accepts_the_handshake_then_closes_at_once() {
    let mut h = hub();
    let mut now = 0;
    let mut delays = vec![];
    for _ in 0..6 {
        up(&mut h, now);
        let [O::Connected(false), O::Reconnect { at_ms }] = h.on_close(now)[..] else { panic!("no reconnect") };
        delays.push(at_ms - now);
        now = at_ms;
    }
    assert_eq!(delays, [2_000, 5_000, 15_000, 60_000, 300_000, 300_000]);
}

#[test]
fn a_connection_that_drops_before_it_is_stable_keeps_its_attempt_count() {
    let mut h = hub();
    up(&mut h, 0);
    h.on_close(0);
    up(&mut h, 2_000);
    // Dropped at 31_999, one millisecond short of stable_ms: the pending reset must not fire later.
    h.on_close(31_999);
    h.on_tick(33_000);
    up(&mut h, 40_000);
    assert_eq!(h.on_close(40_001), [O::Connected(false), O::Reconnect { at_ms: 55_001 }]);
}

#[test]
fn reconnects_when_the_server_goes_silent() {
    let mut h = hub();
    up(&mut h, 0);
    for k in 1..=3 {
        h.on_tick(15_000 * k);
    }
    assert_eq!(h.on_tick(60_000), [O::Close, O::Connected(false), O::Reconnect { at_ms: 62_000 }]);
    // The torn-down connection owes no more pings or timeouts.
    assert_eq!(h.on_tick(120_000), []);
}

#[test]
fn any_frame_counts_as_a_sign_of_life() {
    let options = HubOptions { ping_interval_ms: u64::MAX, ..HubOptions::default() };
    let mut h = Hub::new(options, "this-device".into());
    h.on_open(0);
    assert_eq!(h.on_frame(bin(&[0x7b, 0x7d, 0x1e]), 0), [O::Connected(true), O::WakeAt(30_000)]);
    assert_eq!(strip(h.on_frame(bin(&framed(&[0x91, 0x06])), 30_000)), []);
    assert_eq!(h.on_tick(60_000), [O::WakeAt(90_000)]);
    assert_eq!(h.on_tick(90_000), [O::Close, O::Connected(false), O::Reconnect { at_ms: 92_000 }]);
}

#[test]
fn starts_over_after_a_refused_or_malformed_handshake() {
    let drop_it = [O::Close, O::Reconnect { at_ms: 2_000 }];
    for reply in [
        Frame::Text("{\"error\":\"nope\"}\u{1e}".into()),
        Frame::Text("{\"error\":\"\"}\u{1e}".into()), // stricter than the plugin, which lets an empty error through
        Frame::Text("garbage".into()),
        bin(b"{not json\x1e"),
        bin(&[0xff, 0x1e]),
        Frame::Text("[1]\u{1e}".into()),
        Frame::Text("null\u{1e}".into()),
    ] {
        let mut h = hub();
        h.on_open(0);
        assert_eq!(strip(h.on_frame(reply.clone(), 0)), drop_it, "{reply:?}");
    }
    for reply in ["{\"error\":null}\u{1e}", "{\"error\":false}\u{1e}", "{\"foo\":1}\u{1e}"] {
        let mut h = hub();
        h.on_open(0);
        assert_eq!(strip(h.on_frame(Frame::Text(reply.into()), 0)), [O::Connected(true)], "{reply}");
    }
}

#[test]
fn starts_over_after_malformed_messagepack_and_reports_nothing() {
    for bytes in [
        framed(&[0x92, 0x01]),
        vec![0x80],                   // truncated length prefix
        vec![0x05, 0xc0],             // truncated message
        vec![0x80, 0x80, 0x80, 0x08], // 16 MiB message
        framed(&[0x91, 0x92, 0x01]),  // truncated nested array
    ] {
        let mut h = hub();
        up(&mut h, 0);
        assert_eq!(strip(h.on_frame(bin(&bytes), 0)), [O::Close, O::Connected(false), O::Reconnect { at_ms: 2_000 }]);
        assert_eq!(strip(h.on_tick(10_000)), []);
    }
}

#[test]
fn starts_over_when_the_server_sends_close_and_reconnects_once_for_two() {
    let expected = [O::Close, O::Connected(false), O::Reconnect { at_ms: 2_000 }];
    let mut h = hub();
    up(&mut h, 0);
    assert_eq!(strip(h.on_frame(bin(&framed(&[0x91, 0x07])), 0)), expected);
    let mut h = hub();
    up(&mut h, 0);
    let twice = [framed(&[0x91, 0x07]), framed(&[0x91, 0x07])].concat();
    assert_eq!(strip(h.on_frame(bin(&twice), 0)), expected);
}

#[test]
fn stays_connected_and_reports_nothing_for_messages_it_does_not_act_on() {
    let rm = receive_message();
    let with = |tail: &[u8]| framed(&[&rm[..], tail].concat());
    let other = framed(&[&[0x95, 0x01, 0x80, 0xc0][..], &enc("Other"), &[0x91, 0x81], &enc("Type"), &[0x00]].concat());
    let no_type = with(&[&[0x91, 0x81][..], &enc("Foo"), &[0x00]].concat());
    let string_type = with(&[&[0x91, 0x81][..], &enc("Type"), &enc("1")].concat());
    for data in [
        framed(&[0xc0]),                   // nil
        framed(&[0x90]),                   // empty array
        framed(&[0x91, 0x06]),             // ping
        framed(&[0x91, 0x02]),             // another message type
        framed(&[0x93, 0x01, 0x80, 0xc0]), // no method
        other,
        with(&[0xc0]),                   // no arguments
        with(&[0x91, 0xc0]),             // nil notification
        with(&[0x91, 0x00]),             // number for a notification
        with(&[0x91, 0xc4, 0x01, 0x00]), // bytes for a notification
        no_type,
        string_type,
    ] {
        let mut h = hub();
        up(&mut h, 0);
        assert_eq!(strip(h.on_frame(bin(&data), 0)), [], "{data:?}");
        assert_eq!(strip(h.on_tick(10_000)), []);
        assert_eq!(h.on_close(10_000), [O::Connected(false), O::Reconnect { at_ms: 12_000 }], "still connected");
    }
}

#[test]
fn accepts_the_handshake_as_a_text_frame_and_ignores_text_after_it() {
    let mut h = hub();
    h.on_open(0);
    assert_eq!(strip(h.on_frame(Frame::Text("{}\u{1e}".into()), 0)), [O::Connected(true)]);
    assert_eq!(strip(h.on_frame(Frame::Text("{\"type\":1,\"target\":\"ReceiveMessage\"}\u{1e}".into()), 0)), []);
    assert_eq!(strip(h.on_tick(10_000)), []);
}

#[test]
fn a_transport_that_ends_before_the_handshake_only_schedules_a_reconnect() {
    let mut h = hub();
    // No URL, a failed connect and so on: each costs one step of the backoff, the last step repeats.
    let mut at = vec![];
    for _ in 0..7 {
        let [O::Reconnect { at_ms }] = h.on_close(0)[..] else { panic!("no reconnect") };
        at.push(at_ms);
    }
    assert_eq!(at, [2_000, 5_000, 15_000, 60_000, 300_000, 300_000, 300_000]);
}

#[test]
fn an_empty_backoff_list_still_waits_a_millisecond_and_custom_options_apply() {
    let options = HubOptions {
        ping_interval_ms: 10,
        server_timeout_ms: 20,
        settle_ms: 5,
        min_interval_ms: 7,
        backoff_ms: vec![],
        stable_ms: 3,
    };
    let mut h = Hub::new(options, "this-device".into());
    assert_eq!(h.on_open(100), [O::Send(Frame::Text(HANDSHAKE.into())), O::WakeAt(120)]);
    assert_eq!(h.on_frame(bin(&[0x7b, 0x7d, 0x1e]), 100), [O::Connected(true), O::WakeAt(103)]);
    h.on_frame(bin(&invocation(0, Some(OTHER))), 100);
    assert_eq!(h.on_tick(105), [O::Changed, O::WakeAt(110)]);
    assert_eq!(strip(h.on_frame(bin(&invocation(0, Some(OTHER))), 106)), []);
    assert_eq!(h.on_tick(112), [O::Send(bin(&[0x02, 0x91, 0x06])), O::Changed, O::WakeAt(122)]);
    assert_eq!(h.on_close(112), [O::Connected(false), O::Reconnect { at_ms: 113 }]);
}

// ---- run_hub ----

enum Step {
    Recv(Frame),
    Fail,
    Hang,
    /// Always ready; every receive takes a second of the fake clock.
    Spin(Frame),
}

struct Sock {
    steps: VecDeque<Step>,
    sent: Rc<RefCell<Vec<Frame>>>,
    closed: Rc<Cell<u32>>,
    time: Rc<Cell<i64>>,
    fail_send: bool,
}

impl EventSocket for Sock {
    async fn send(&mut self, frame: Frame) -> Result<(), PortError> {
        if self.fail_send {
            return Err(PortError("send".into()));
        }
        self.sent.borrow_mut().push(frame);
        Ok(())
    }
    async fn recv(&mut self) -> Option<Result<Frame, PortError>> {
        match self.steps.pop_front() {
            Some(Step::Recv(f)) => Some(Ok(f)),
            Some(Step::Spin(f)) => {
                self.time.set(self.time.get() + 1_000);
                self.steps.push_front(Step::Spin(f.clone()));
                Some(Ok(f))
            }
            Some(Step::Fail) => Some(Err(PortError("recv".into()))),
            Some(Step::Hang) => {
                self.steps.push_front(Step::Hang);
                std::future::pending().await
            }
            None => None,
        }
    }
    async fn close(&mut self) {
        self.closed.set(self.closed.get() + 1);
    }
}

#[derive(Default)]
struct Fake {
    socks: RefCell<VecDeque<Option<Sock>>>,
    urls: RefCell<Vec<String>>,
    sent: Rc<RefCell<Vec<Frame>>>,
    closed: Rc<Cell<u32>>,
    time: Rc<Cell<i64>>,
}

impl Fake {
    fn clock(&self) -> StepClock {
        StepClock(self.time.clone())
    }
    fn sock(&self, steps: Vec<Step>, fail_send: bool) -> Option<Sock> {
        Some(Sock {
            steps: steps.into(),
            sent: self.sent.clone(),
            closed: self.closed.clone(),
            time: self.time.clone(),
            fail_send,
        })
    }
    fn push(&self, s: Option<Sock>) {
        self.socks.borrow_mut().push_back(s);
    }
}

impl Events for Fake {
    type Socket = Sock;
    async fn connect(&self, url: &str) -> Result<Sock, PortError> {
        self.urls.borrow_mut().push(url.into());
        self.socks.borrow_mut().pop_front().flatten().ok_or(PortError("connect".into()))
    }
}

/// Sleeping moves time on, so a hub waiting for its next deadline gets there.
struct StepClock(Rc<Cell<i64>>);

impl Clock for StepClock {
    fn now_ms(&self) -> i64 {
        self.0.get()
    }
    async fn sleep_ms(&self, ms: u64) {
        self.0.set(self.0.get() + i64::try_from(ms).unwrap());
    }
}

/// Every run_hub test goes through here, so the driver is instantiated (and its lines counted) once.
fn run(fake: &Fake, clock: &StepClock, urls: &[Option<&str>], changes: &Cell<u32>, stop: &dyn Fn() -> bool) {
    let queue: RefCell<VecDeque<Option<String>>> = RefCell::new(urls.iter().map(|u| u.map(String::from)).collect());
    let mut on_change = || changes.set(changes.get() + 1);
    block_on(run_hub(fake, clock, async || queue.borrow_mut().pop_front().flatten(), &mut hub(), &mut on_change, stop));
}

#[test]
fn run_hub_reports_a_change() {
    let fake = Fake::default();
    let steps = vec![Step::Recv(bin(&[0x7b, 0x7d, 0x1e])), Step::Recv(bin(&invocation(0, Some(OTHER)))), Step::Hang];
    fake.push(fake.sock(steps, false));
    let clock = fake.clock();
    let changes = Cell::new(0);
    run(&fake, &clock, &[Some("wss://bw.test/hub")], &changes, &|| changes.get() > 0);
    assert_eq!(changes.get(), 1);
    assert_eq!(*fake.urls.borrow(), ["wss://bw.test/hub"]);
    assert_eq!(*fake.sent.borrow(), [Frame::Text(HANDSHAKE.into())]);
    assert_eq!(fake.closed.get(), 1);
    assert_eq!(clock.now_ms(), 1_000, "waited for the settle time, no longer");
}

#[test]
fn run_hub_backs_off_when_no_url_can_be_had_or_the_connect_fails() {
    let fake = Fake::default();
    fake.push(None);
    fake.push(fake.sock(vec![], false));
    let clock = fake.clock();
    run(&fake, &clock, &[None, Some("a"), Some("b")], &Cell::new(0), &|| fake.urls.borrow().len() >= 2);
    assert_eq!(*fake.urls.borrow(), ["a", "b"]);
    assert_eq!(clock.now_ms(), 7_000, "2 s, then 5 s");
}

#[test]
fn run_hub_stops_during_the_wait_for_a_reconnect() {
    let fake = Fake::default();
    let clock = fake.clock();
    run(&fake, &clock, &[None], &Cell::new(0), &|| clock.now_ms() >= 2_000);
    assert!(fake.urls.borrow().is_empty());
    assert_eq!(clock.now_ms(), 2_000);
}

#[test]
fn run_hub_starts_over_after_a_send_fails() {
    let fake = Fake::default();
    fake.push(fake.sock(vec![Step::Hang], true));
    run(&fake, &fake.clock(), &[Some("u")], &Cell::new(0), &|| fake.closed.get() >= 1);
    assert_eq!(fake.closed.get(), 1);
    assert!(fake.sent.borrow().is_empty());
}

#[test]
fn run_hub_follows_a_close_from_the_server() {
    let fake = Fake::default();
    let steps = vec![Step::Recv(bin(&[0x7b, 0x7d, 0x1e])), Step::Recv(bin(&framed(&[0x91, 0x07])))];
    fake.push(fake.sock(steps, false));
    run(&fake, &fake.clock(), &[Some("u")], &Cell::new(0), &|| fake.closed.get() >= 1);
    assert_eq!(fake.closed.get(), 1);
    assert_eq!(fake.sent.borrow().len(), 1, "only the handshake");
}

#[test]
fn run_hub_reconnects_after_the_socket_ends_or_fails() {
    let fake = Fake::default();
    fake.push(fake.sock(vec![], false));
    fake.push(fake.sock(vec![Step::Fail], false));
    fake.push(fake.sock(vec![], false));
    let clock = fake.clock();
    run(&fake, &clock, &[Some("u"); 3], &Cell::new(0), &|| fake.urls.borrow().len() >= 3);
    assert_eq!(fake.closed.get(), 3);
    assert_eq!(clock.now_ms(), 7_000);
}

#[test]
fn run_hub_reports_a_change_while_waiting_to_reconnect() {
    let fake = Fake::default();
    let steps = vec![Step::Recv(bin(&[0x7b, 0x7d, 0x1e])), Step::Recv(bin(&invocation(0, Some(OTHER)))), Step::Fail];
    fake.push(fake.sock(steps, false));
    let clock = fake.clock();
    let changes = Cell::new(0);
    run(&fake, &clock, &[Some("u"), Some("u")], &changes, &|| changes.get() > 0);
    assert_eq!(changes.get(), 1);
    assert_eq!(clock.now_ms(), 1_000, "at the settle time, before the reconnect at 2 s");
    assert_eq!(fake.urls.borrow().len(), 1);
}

#[test]
fn run_hub_ticks_even_when_the_server_never_stops_sending() {
    let fake = Fake::default();
    let steps = vec![Step::Recv(bin(&[0x7b, 0x7d, 0x1e])), Step::Spin(bin(&framed(&[0x91, 0x06])))];
    fake.push(fake.sock(steps, false));
    let clock = fake.clock();
    run(&fake, &clock, &[Some("u")], &Cell::new(0), &|| clock.now_ms() > 20_000);
    assert!(fake.sent.borrow().iter().any(|f| *f == bin(&[0x02, 0x91, 0x06])), "a ping went out");
}
