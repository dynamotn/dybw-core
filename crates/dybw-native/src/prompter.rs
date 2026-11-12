//! Asks the user things through a pinentry program (Assuan protocol), the
//! same mechanism gpg-agent uses: `pinentry-gnome3`, `pinentry-qt`, ... all
//! work, and tests plug in a scripted one.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use dybw_core::vault::write::HistoryAnswer;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use zeroize::Zeroizing;

use crate::config::Trust;

/// Answer to an access confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    Once,
    Always,
    Deny,
}

#[derive(Debug, thiserror::Error)]
pub enum PromptError {
    #[error("could not run the prompter {0:?}: {1}")]
    Spawn(String, std::io::Error),
    #[error("refusing to run the prompter: {0}")]
    Untrusted(String),
    #[error("prompter protocol error: {0}")]
    Protocol(String),
    #[error("the prompt timed out")]
    Timeout,
}

// libgpg-error codes as pinentry reports them (source 5 = pinentry).
const ERR_CANCELED: &str = "83886179";
const ERR_NOT_CONFIRMED: &str = "83886194";

/// The error code of an `ERR` reply: its first word, compared whole.
fn err_code(err: &str) -> &str {
    err.split_whitespace().next().unwrap_or_default()
}

/// Whether an `ERR` reply is the user's own "no": cancel or not confirmed.
fn is_users_no(err: &str) -> bool {
    matches!(err_code(err), ERR_CANCELED | ERR_NOT_CONFIRMED)
}

/// Checks the program again right before it runs (ADR 0008: a pinentry
/// that became writable since the daemon started is refused).
pub type Guard = std::sync::Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// The variables a pinentry may inherit: the session's display and locale,
/// nothing that points at a terminal (`GPG_TTY`, `TERM`), a search path
/// (`PATH`), a loader (`LD_*`, `DYLD_*`) or pinentry's own data
/// (`PINENTRY_USER_DATA`). The caller of the constructor picks the list; it
/// is never derived from a request.
pub const SESSION_ENV: &[&str] = &[
    "XDG_SESSION_TYPE",
    "DISPLAY",
    "XAUTHORITY",
    "XMODIFIERS",
    "WAYLAND_DISPLAY",
    "QT_QPA_PLATFORM",
    "GTK_IM_MODULE",
    "DBUS_SESSION_BUS_ADDRESS",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "HOME",
    "USER",
    "LOGNAME",
];

/// The longest reply line, and the longest PIN, taken from a pinentry.
const MAX_REPLY: usize = 64 * 1024;

#[derive(Clone)]
pub struct Prompter {
    /// The canonical absolute path `Trust::check` resolved (tests: any path).
    program: String,
    timeout: Duration,
    guard: Option<Guard>,
    env: &'static [&'static str],
}

struct Conversation {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

/// Characters that are not controls but still change what text looks like:
/// the line and paragraph separators (U+2028, U+2029) and every character of
/// general category Cf (Unicode 15.1), which std cannot query: soft hyphen,
/// Arabic and Syriac marks, ZWSP/ZWNJ/ZWJ, LRM/RLM/ALM, the bidi embeddings,
/// overrides and isolates, invisible operators, BOM, interlinear
/// annotation, a few script-specific format marks, and the tag characters.
const INVISIBLE: &[(char, char)] = &[
    ('\u{ad}', '\u{ad}'),
    ('\u{600}', '\u{605}'),
    ('\u{61c}', '\u{61c}'),
    ('\u{6dd}', '\u{6dd}'),
    ('\u{70f}', '\u{70f}'),
    ('\u{890}', '\u{891}'),
    ('\u{8e2}', '\u{8e2}'),
    ('\u{180e}', '\u{180e}'),
    ('\u{200b}', '\u{200f}'),
    ('\u{2028}', '\u{202e}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206f}'),
    ('\u{feff}', '\u{feff}'),
    ('\u{fff9}', '\u{fffb}'),
    ('\u{110bd}', '\u{110bd}'),
    ('\u{110cd}', '\u{110cd}'),
    ('\u{13430}', '\u{1343f}'),
    ('\u{1bca0}', '\u{1bca3}'),
    ('\u{1d173}', '\u{1d17a}'),
    ('\u{e0001}', '\u{e0001}'),
    ('\u{e0020}', '\u{e007f}'),
];

/// Whether `c` is in [`INVISIBLE`].
pub fn is_invisible(c: char) -> bool {
    INVISIBLE.iter().any(|&(lo, hi)| (lo..=hi).contains(&c))
}

/// `s` on one line for a prompt: line breaks, every other control character
/// and every invisible format character (bidi overrides included) become
/// U+FFFD, so a file name or a label cannot add or reorder text.
pub fn one_line(s: &str) -> String {
    s.chars().map(|c| if c.is_control() || is_invisible(c) { '\u{fffd}' } else { c }).collect()
}

/// `s` without what a dialog must not obey: every control character but the
/// line break, and the invisible and bidi format characters.
fn printable(s: &str) -> String {
    s.chars().filter(|&c| c == '\n' || !(c.is_control() || is_invisible(c))).collect()
}

fn escape(s: &str) -> String {
    s.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}

/// `s` with its `%XX` escapes decoded; bytes that are not UTF-8 are an error, never U+FFFD.
fn unescape(s: &str) -> Result<Zeroizing<String>, PromptError> {
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        if c == b'%'
            && i + 2 < bytes.len()
            && let Some(b) = bytes
                .get(i + 1..i + 3)
                .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(c);
        i += 1;
    }
    let text = std::str::from_utf8(&out).map_err(|_| PromptError::Protocol("reply is not valid UTF-8".into()))?;
    let mut copy = Zeroizing::new(String::with_capacity(text.len()));
    copy.push_str(text);
    Ok(copy)
}

/// A failed read from or write to the prompter.
fn io_error(e: std::io::Error) -> PromptError {
    PromptError::Protocol(e.to_string())
}

enum Reply {
    Ok(Option<Zeroizing<String>>),
    Err(String),
}

impl Conversation {
    async fn start(program: &str, env: &[&str]) -> Result<Self, PromptError> {
        let mut command = Command::new(program);
        command.env_clear();
        for name in env {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        // Its own process group, so a terminal's signals and job control do
        // not reach it. shortcut: no `setsid` (it needs `unsafe`) and no
        // group kill, so a timeout kills the pinentry but not a child of its
        // own; upgrade when the agent can spend an `unsafe`-free kill of `-pgid`.
        let mut child = command
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| PromptError::Spawn(program.to_owned(), e))?;
        let stdin = child.stdin.take().ok_or(PromptError::Protocol("no stdin".into()))?;
        let stdout = BufReader::new(child.stdout.take().ok_or(PromptError::Protocol("no stdout".into()))?);
        let mut c = Conversation { child, stdin, stdout };
        match c.read_reply().await? {
            Reply::Ok(_) => Ok(c),
            Reply::Err(e) => Err(PromptError::Protocol(format!("greeting: {e}"))),
        }
    }

    async fn read_reply(&mut self) -> Result<Reply, PromptError> {
        let mut data: Option<Zeroizing<String>> = None;
        loop {
            // One buffer, never grown: no stray copy of a PIN is left behind.
            let mut buf = Zeroizing::new(Vec::with_capacity(MAX_REPLY + 1));
            let limit = u64::try_from(MAX_REPLY + 1).unwrap_or(u64::MAX);
            let n = (&mut self.stdout).take(limit).read_until(b'\n', &mut buf).await.map_err(io_error)?;
            if n == 0 {
                return Err(PromptError::Protocol("prompter exited".into()));
            }
            if n > MAX_REPLY {
                return Err(PromptError::Protocol("reply line too long".into()));
            }
            let line =
                std::str::from_utf8(&buf).map_err(|_| PromptError::Protocol("reply is not valid UTF-8".into()))?;
            let line = line.trim_end_matches(['\r', '\n']);
            if line == "OK" || line.starts_with("OK ") {
                return Ok(Reply::Ok(data));
            }
            if let Some(rest) = line.strip_prefix("ERR ") {
                return Ok(Reply::Err(rest.to_owned()));
            }
            if let Some(d) = line.strip_prefix("D ") {
                let chunk = unescape(d)?;
                let pin = data.get_or_insert_with(|| Zeroizing::new(String::with_capacity(MAX_REPLY)));
                if pin.len() + chunk.len() > MAX_REPLY {
                    return Err(PromptError::Protocol("reply too long".into()));
                }
                pin.push_str(&chunk);
            }
            // "S" status and "#" comment lines are ignored.
        }
    }

    async fn command(&mut self, cmd: &str) -> Result<Reply, PromptError> {
        self.stdin.write_all(cmd.as_bytes()).await.map_err(io_error)?;
        self.stdin.write_all(b"\n").await.map_err(io_error)?;
        self.stdin.flush().await.map_err(io_error)?;
        self.read_reply().await
    }

    async fn set(&mut self, cmd: &str, value: &str) -> Result<(), PromptError> {
        match self.command(&format!("{cmd} {}", escape(&printable(value)))).await? {
            Reply::Ok(_) => Ok(()),
            Reply::Err(e) => Err(PromptError::Protocol(format!("{cmd}: {e}"))),
        }
    }

    async fn finish(mut self) {
        let _ = self.command("BYE").await;
        let _ = self.child.wait().await;
    }
}

impl Prompter {
    /// A prompter for `pinentry` once `trust` accepts it. It runs the
    /// canonical path `Trust::check` resolved, and checks that path again
    /// before every start (ADR 0008; the gap between that check and the
    /// spawn is the accepted residual risk under the install-prefix rule).
    /// The child sees only the variables of `env` (see [`SESSION_ENV`]).
    pub fn trusted(
        trust: Trust,
        pinentry: &str,
        timeout: Duration,
        env: &'static [&'static str],
    ) -> anyhow::Result<Self> {
        let (resolved, _) = trust.check(pinentry)?;
        let guard: Guard =
            std::sync::Arc::new(move |p: &str| trust.verify(Path::new(p)).map(drop).map_err(|e| format!("{e:#}")));
        Ok(Prompter { program: resolved.to_string_lossy().into_owned(), timeout, guard: Some(guard), env })
    }

    /// Any program, unchecked: tests only (the child gets `PATH`).
    #[cfg(test)]
    fn new(program: impl Into<String>, timeout: Duration) -> Self {
        Prompter { program: program.into(), timeout, guard: None, env: &["PATH"] }
    }

    /// A prompter that runs `guard` on the program before every start.
    #[cfg(test)]
    fn guarded(program: impl Into<String>, timeout: Duration, guard: Guard) -> Self {
        Prompter { guard: Some(guard), ..Self::new(program, timeout) }
    }

    async fn start(&self) -> Result<Conversation, PromptError> {
        if let Some(guard) = &self.guard {
            guard(&self.program).map_err(PromptError::Untrusted)?;
        }
        Conversation::start(&self.program, self.env).await
    }

    /// Asks for a password with bwss's wording; `None` when the user cancelled.
    pub async fn password(
        &self,
        description: &str,
        error: Option<&str>,
    ) -> Result<Option<Zeroizing<String>>, PromptError> {
        self.ask_password("Unlock keyring", "Master password:", description, error).await
    }

    /// Asks for a password under a caller-set `title` and `prompt`; `None`
    /// when the user cancelled. Every text is sanitised like `description`.
    pub async fn ask_password(
        &self,
        title: &str,
        prompt: &str,
        description: &str,
        error: Option<&str>,
    ) -> Result<Option<Zeroizing<String>>, PromptError> {
        tokio::time::timeout(self.timeout, async {
            let mut c = self.start().await?;
            c.set("SETTITLE", title).await?;
            c.set("SETDESC", description).await?;
            c.set("SETPROMPT", prompt).await?;
            if let Some(e) = error {
                c.set("SETERROR", e).await?;
            }
            let reply = c.command("GETPIN").await?;
            c.finish().await;
            match reply {
                // No data line: nothing was entered, which is a cancel.
                Reply::Ok(pin) => Ok(pin),
                Reply::Err(e) if err_code(&e) == ERR_CANCELED => Ok(None),
                Reply::Err(e) => Err(PromptError::Protocol(format!("GETPIN: {e}"))),
            }
        })
        .await
        .map_err(|_| PromptError::Timeout)?
    }

    /// Asks a history question (ADR 0016) with its three answers: "Write to
    /// the login" (OK), "Keep the app's value separate" (not OK) and
    /// "Cancel". `None` is the user's cancel.
    pub async fn history(&self, description: &str) -> Result<Option<HistoryAnswer>, PromptError> {
        tokio::time::timeout(self.timeout, async {
            let mut c = self.start().await?;
            c.set("SETTITLE", "Keyring write").await?;
            c.set("SETDESC", description).await?;
            c.set("SETOK", "Write to the login").await?;
            c.set("SETNOTOK", "Keep the app's value separate").await?;
            c.set("SETCANCEL", "Cancel").await?;
            let reply = c.command("CONFIRM").await?;
            c.finish().await;
            match reply {
                Reply::Ok(_) => Ok(Some(HistoryAnswer::WriteToLogin)),
                Reply::Err(e) if err_code(&e) == ERR_NOT_CONFIRMED => Ok(Some(HistoryAnswer::KeepSeparate)),
                Reply::Err(e) if err_code(&e) == ERR_CANCELED => Ok(None),
                Reply::Err(e) => Err(PromptError::Protocol(format!("CONFIRM: {e}"))),
            }
        })
        .await
        .map_err(|_| PromptError::Timeout)?
    }

    /// Asks whether an application may use an item. Without `offer_always`
    /// there is no second question: the answer is `Once` or `Deny`.
    pub async fn confirm(&self, description: &str, offer_always: bool) -> Result<Confirm, PromptError> {
        self.ask_confirm("Keyring access", description, offer_always).await
    }

    /// [`Self::confirm`] under a caller-set `title`.
    pub async fn ask_confirm(
        &self,
        title: &str,
        description: &str,
        offer_always: bool,
    ) -> Result<Confirm, PromptError> {
        tokio::time::timeout(self.timeout, async {
            let mut c = self.start().await?;
            c.set("SETTITLE", title).await?;
            c.set("SETDESC", description).await?;
            c.set("SETOK", "Allow").await?;
            c.set("SETCANCEL", "Deny").await?;
            // Only an explicit OK grants anything. Cancel and "not confirmed"
            // are the user's no; any other error means the question was never
            // put (pinentry-curses without a terminal, ...) and is a failure.
            let allowed = match c.command("CONFIRM").await? {
                Reply::Ok(_) => true,
                Reply::Err(e) if is_users_no(&e) => false,
                Reply::Err(e) => {
                    c.finish().await;
                    return Err(PromptError::Protocol(format!("CONFIRM: {e}")));
                }
            };
            if !allowed || !offer_always {
                c.finish().await;
                return Ok(if allowed { Confirm::Once } else { Confirm::Deny });
            }
            c.set("SETDESC", "Remember this decision for this application?").await?;
            c.set("SETOK", "Always allow").await?;
            c.set("SETCANCEL", "Only this time").await?;
            let remember = matches!(c.command("CONFIRM").await?, Reply::Ok(_));
            c.finish().await;
            Ok(if remember { Confirm::Always } else { Confirm::Once })
        })
        .await
        .map_err(|_| PromptError::Timeout)?
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_guarded_prompter_checks_the_program_before_each_start() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        let refuse: Guard = std::sync::Arc::new(move |p: &str| {
            log.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(p.to_owned());
            Err(format!("{p} became writable"))
        });
        let p = Prompter::guarded("/nonexistent/pinentry", Duration::from_secs(1), refuse);
        let e = p.password("x", None).await.err().map(|e| e.to_string()).unwrap_or_default();
        assert_eq!(e, "refusing to run the prompter: /nonexistent/pinentry became writable");
        assert!(matches!(p.confirm("x", true).await, Err(PromptError::Untrusted(_))));
        assert_eq!(
            seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(),
            2,
            "checked before every start"
        );

        let allow: Guard = std::sync::Arc::new(|_: &str| Ok(()));
        let p = Prompter::guarded("/nonexistent/pinentry", Duration::from_secs(1), allow);
        assert!(matches!(p.password("x", None).await, Err(PromptError::Spawn(..))), "allowed, then started");
    }

    /// A scripted pinentry from `tests/fixtures/pinentry/`.
    fn scripted(name: &str, timeout: Duration) -> Prompter {
        Prompter::new(format!("{}/tests/fixtures/pinentry/{name}", env!("CARGO_MANIFEST_DIR")), timeout)
    }

    /// The message of the error in `result`, if it is one; a reply is never printed.
    fn error_of<T>(result: Result<T, PromptError>) -> Option<String> {
        result.err().as_ref().map(ToString::to_string)
    }

    const LONG: Duration = Duration::from_secs(20);

    #[tokio::test]
    async fn a_pin_in_several_data_lines_is_joined_and_status_lines_are_ignored() {
        let pin = scripted("chunked_pin.sh", LONG).password("d", None).await;
        assert_eq!(pin.ok().flatten().as_deref().map(String::as_str), Some("abc100%"));
    }

    #[tokio::test]
    async fn the_error_of_the_last_attempt_is_shown_in_the_dialog() {
        let p = scripted("echo_error.sh", LONG);
        let pin = p.password("d", Some("Wrong password, 50%\nTry again")).await;
        // SETERROR is escaped on the wire; the script hands it back as it got
        // it, and the reply is unescaped again: the text makes the round trip.
        assert_eq!(pin.ok().flatten().as_deref().map(String::as_str), Some("Wrong password, 50%\nTry again"));
        let pin = p.password("d", None).await;
        assert_eq!(pin.ok().flatten().as_deref().map(String::as_str), Some(""), "no error, nothing shown");
    }

    #[tokio::test]
    async fn cancelling_the_dialog_is_no_password_and_no_error() {
        let pin = scripted("cancelled.sh", LONG).password("d", None).await;
        assert!(matches!(pin, Ok(None)), "cancelling is neither a password nor an error");
    }

    #[tokio::test]
    async fn a_pinentry_that_refuses_the_greeting_is_a_protocol_error() {
        let p = scripted("greeting_err.sh", LONG);
        assert_eq!(
            error_of(p.password("d", None).await).as_deref(),
            Some("prompter protocol error: greeting: 83886360 no display")
        );
        assert_eq!(
            error_of(p.confirm("d", false).await).as_deref(),
            Some("prompter protocol error: greeting: 83886360 no display")
        );
    }

    #[tokio::test]
    async fn a_pinentry_that_refuses_an_option_names_it() {
        let p = scripted("set_err.sh", LONG);
        assert_eq!(
            error_of(p.password("d", None).await).as_deref(),
            Some("prompter protocol error: SETTITLE: 83886360 option refused")
        );
    }

    #[tokio::test]
    async fn a_getpin_error_that_is_not_a_cancel_is_a_protocol_error() {
        let p = scripted("getpin_err.sh", LONG);
        assert_eq!(
            error_of(p.password("d", None).await).as_deref(),
            Some("prompter protocol error: GETPIN: 83918950 Inappropriate ioctl for device")
        );
    }

    #[tokio::test]
    async fn output_that_is_not_text_is_a_protocol_error() {
        let p = scripted("not_utf8.sh", LONG);
        let e = error_of(p.password("d", None).await).unwrap_or_default().to_lowercase();
        assert!(e.starts_with("prompter protocol error: "), "{e}");
        assert!(e.contains("utf-8"), "{e}");
    }

    #[tokio::test]
    async fn a_pinentry_that_stopped_listening_is_a_protocol_error() {
        let p = scripted("stdin_closed.sh", LONG);
        assert_eq!(
            error_of(p.password("d", None).await).as_deref(),
            Some("prompter protocol error: Broken pipe (os error 32)")
        );
    }

    #[tokio::test]
    async fn the_caller_sets_the_title_and_prompt_and_the_old_helpers_keep_theirs() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pinentry");
        let body = "#!/bin/sh\necho OK\nwhile IFS= read -r l; do\n  printf '%s\\n' \"$l\" >> \"$0.log\"\n  case \"$l\" in\n    GETPIN*) echo OK ;;\n    BYE*) echo OK; exit 0 ;;\n    *) echo OK ;;\n  esac\ndone\n";
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let p = Prompter::new(path.to_string_lossy(), LONG);
        let log = || std::fs::read_to_string(path.with_extension("log")).unwrap_or_default();
        let run = |log: String| log.lines().map(str::to_owned).collect::<Vec<_>>();

        p.ask_password("Unlock\u{202e}Vault", "Passphrase:\n", "d", None).await.unwrap();
        let lines = run(log());
        assert!(lines.contains(&"SETTITLE UnlockVault".into()), "{lines:?}");
        assert!(lines.contains(&"SETPROMPT Passphrase:%0A".into()), "{lines:?}");
        std::fs::remove_file(path.with_extension("log")).unwrap();

        p.password("d", None).await.unwrap();
        let lines = run(log());
        assert!(lines.contains(&"SETTITLE Unlock keyring".into()), "{lines:?}");
        assert!(lines.contains(&"SETPROMPT Master password:".into()), "{lines:?}");
        std::fs::remove_file(path.with_extension("log")).unwrap();

        p.ask_confirm("Vault access", "d", false).await.unwrap();
        assert!(run(log()).contains(&"SETTITLE Vault access".into()));
        std::fs::remove_file(path.with_extension("log")).unwrap();
        p.confirm("d", false).await.unwrap();
        assert!(run(log()).contains(&"SETTITLE Keyring access".into()));
    }

    #[tokio::test]
    async fn a_history_question_has_three_answers() {
        let dir = tempfile::tempdir().unwrap();
        let answering = |reply: &str| {
            use std::os::unix::fs::PermissionsExt;
            let path = dir.path().join(format!("pinentry-{}", reply.len()));
            let body = format!(
                "#!/bin/sh\necho OK\nwhile IFS= read -r l; do\n  printf '%s\\n' \"$l\" >> \"$0.log\"\n  case \"$l\" in\n    CONFIRM*) echo '{reply}' ;;\n    BYE*) echo OK; exit 0 ;;\n    *) echo OK ;;\n  esac\ndone\n"
            );
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            (Prompter::new(path.to_string_lossy(), LONG), path)
        };
        let (p, path) = answering("OK");
        assert_eq!(p.history("d").await.ok().flatten(), Some(HistoryAnswer::WriteToLogin));
        let log = std::fs::read_to_string(path.with_extension("log")).unwrap_or_default();
        for line in ["SETOK Write to the login", "SETNOTOK Keep the app's value separate", "SETCANCEL Cancel"] {
            assert!(log.lines().any(|l| l == line), "{line}: {log}");
        }
        let (p, _) = answering("ERR 83886194 Not confirmed");
        assert_eq!(p.history("d").await.ok().flatten(), Some(HistoryAnswer::KeepSeparate));
        let (p, _) = answering("ERR 83886179 Operation cancelled");
        assert!(matches!(p.history("d").await, Ok(None)));
        let (p, _) = answering("ERR 1 no tty");
        assert_eq!(error_of(p.history("d").await).as_deref(), Some("prompter protocol error: CONFIRM: 1 no tty"));
    }

    /// A pinentry that answers its n-th CONFIRM with `replies[n - 1]` and everything else with OK.
    fn confirming(dir: &std::path::Path, replies: &[&str]) -> Prompter {
        use std::os::unix::fs::PermissionsExt;
        let arms: String = replies.iter().enumerate().map(|(i, r)| format!("{}) echo '{r}' ;; ", i + 1)).collect();
        let body = format!(
            "#!/bin/sh\necho OK\nn=0\nwhile IFS= read -r l; do\n  case \"$l\" in\n    CONFIRM*) n=$((n+1)); case $n in {arms}esac ;;\n    BYE*) echo OK; exit 0 ;;\n    *) echo OK ;;\n  esac\ndone\n"
        );
        let path = dir.join("pinentry");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Prompter::new(path.to_string_lossy(), LONG)
    }

    #[tokio::test]
    async fn a_confirmation_is_once_always_or_deny() {
        const NO: &str = "ERR 83886179 Operation cancelled";
        let dir = tempfile::tempdir().unwrap();
        // Without the second question only an explicit OK allows.
        assert!(matches!(confirming(dir.path(), &["OK"]).confirm("d", false).await, Ok(Confirm::Once)));
        assert!(matches!(confirming(dir.path(), &[NO]).confirm("d", false).await, Ok(Confirm::Deny)));
        assert!(matches!(confirming(dir.path(), &[NO]).confirm("d", true).await, Ok(Confirm::Deny)));
        // The second question remembers the decision, or not.
        assert!(matches!(confirming(dir.path(), &["OK", "OK"]).confirm("d", true).await, Ok(Confirm::Always)));
        assert!(matches!(confirming(dir.path(), &["OK", NO]).confirm("d", true).await, Ok(Confirm::Once)));
        // An error that is not the user's no means the question was never put: never an allow.
        let e = confirming(dir.path(), &["ERR 1 no tty"]).confirm("d", true).await;
        assert_eq!(error_of(e).as_deref(), Some("prompter protocol error: CONFIRM: 1 no tty"));
    }

    #[tokio::test]
    async fn a_pinentry_that_exits_mid_conversation_is_a_protocol_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pinentry");
        std::fs::write(&path, "#!/bin/sh\necho OK\nread -r l\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let p = Prompter::new(path.to_string_lossy(), LONG);
        assert_eq!(error_of(p.password("d", None).await).as_deref(), Some("prompter protocol error: prompter exited"));
    }

    /// The probe's answer (`CARGO_MANIFEST_DIR=<value> pid pgid`) for a child started with `env`.
    async fn probe(env: &'static [&'static str]) -> String {
        let mut p = scripted("env_probe.sh", LONG);
        p.env = env;
        p.password("d", None).await.ok().flatten().map(|pin| pin.as_str().to_owned()).unwrap_or_default()
    }

    #[tokio::test]
    async fn the_child_sees_only_the_allowlisted_variables() {
        // The probed variable is set by cargo for every test run. Not allowlisted: absent
        // (and an allowlisted name that is unset is skipped).
        let seen = probe(&["NO_SUCH_VARIABLE_FOR_DYBW"]).await;
        assert!(seen.starts_with("CARGO_MANIFEST_DIR=absent "), "{seen}");
        let seen = probe(&["CARGO_MANIFEST_DIR"]).await;
        assert!(seen.starts_with(&format!("CARGO_MANIFEST_DIR={} ", env!("CARGO_MANIFEST_DIR"))), "{seen}");
        assert!(!SESSION_ENV.contains(&"PATH"));
        for name in ["GPG_TTY", "TERM", "PINENTRY_USER_DATA", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"] {
            assert!(!SESSION_ENV.contains(&name), "{name}");
        }
    }

    #[tokio::test]
    async fn the_child_leads_its_own_process_group() {
        let seen = probe(&[]).await;
        let mut ids = seen.rsplit(' ');
        let (pgid, pid) = (ids.next().unwrap(), ids.next().unwrap());
        assert_eq!(pgid, pid, "{seen}");
    }

    #[tokio::test]
    async fn a_trusted_prompter_runs_the_canonical_path_and_checks_it_before_each_start() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let src = format!("{}/tests/fixtures/pinentry/cancelled.sh", env!("CARGO_MANIFEST_DIR"));
        let path = dir.path().canonicalize().unwrap().join("pinentry");
        std::fs::copy(&src, &path).unwrap();
        let owner = std::fs::metadata(&path).unwrap().uid();
        let trust = |uid: u32| Trust {
            search: None,
            user: crate::fsutil::User { uid, groups: Some(vec![]) },
            exe: None,
            home: None,
        };
        let stranger = trust(owner.wrapping_add(1).max(1));
        // The program's owner could replace it: refused at construction.
        assert!(Prompter::trusted(trust(owner), path.to_str().unwrap(), LONG, &["PATH"]).is_err());
        // A relative name is not a path to run.
        assert!(Prompter::trusted(stranger.clone(), "pinentry", LONG, &["PATH"]).is_err());
        let p = Prompter::trusted(stranger, path.to_str().unwrap(), LONG, &["PATH"]).unwrap();
        assert_eq!(p.program, path.to_str().unwrap(), "the canonical absolute path");
        assert!(matches!(p.password("d", None).await, Ok(None)));
        // Writable since: refused before the next start.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o757)).unwrap();
        let e = error_of(p.password("d", None).await).unwrap_or_default();
        assert!(e.starts_with("refusing to run the prompter: "), "{e}");
        assert!(e.contains("writable"), "{e}");
    }

    /// A pinentry whose GETPIN answer is `printf`-built from `body`.
    fn getpin_answers(dir: &std::path::Path, body: &str) -> Prompter {
        use std::os::unix::fs::PermissionsExt;
        let script = format!(
            "#!/bin/sh\necho OK\nwhile IFS= read -r l; do\n  case \"$l\" in\n    GETPIN*) {body} ;;\n    BYE*) echo OK; exit 0 ;;\n    *) echo OK ;;\n  esac\ndone\n"
        );
        let path = dir.join("pinentry");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Prompter::new(path.to_string_lossy(), LONG)
    }

    #[tokio::test]
    async fn a_reply_is_bounded_and_a_missing_pin_is_a_cancel() {
        let dir = tempfile::tempdir().unwrap();
        // 70000 bytes on one line.
        let long = getpin_answers(dir.path(), "printf 'D '; head -c 70000 /dev/zero | tr '\\0' a; echo; echo OK");
        assert_eq!(
            error_of(long.password("d", None).await).as_deref(),
            Some("prompter protocol error: reply line too long")
        );
        // Two lines of 40000: each fits, the PIN does not.
        let two = getpin_answers(
            dir.path(),
            "for i in 1 2; do printf 'D '; head -c 40000 /dev/zero | tr '\\0' a; echo; done; echo OK",
        );
        assert_eq!(error_of(two.password("d", None).await).as_deref(), Some("prompter protocol error: reply too long"));
        // OK without a D line: nothing was entered.
        let none = getpin_answers(dir.path(), "echo OK");
        assert!(matches!(none.password("d", None).await, Ok(None)));
    }

    #[tokio::test]
    async fn an_escaped_byte_that_is_not_utf8_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = getpin_answers(dir.path(), "echo 'D %FF'; echo OK");
        assert_eq!(
            error_of(p.password("d", None).await).as_deref(),
            Some("prompter protocol error: reply is not valid UTF-8")
        );
    }

    #[tokio::test]
    async fn controls_and_invisible_characters_never_reach_the_dialog() {
        let p = scripted("echo_error.sh", LONG);
        let pin = p.password("d", Some("a\u{1b}[2Jb\u{202e}c\td\u{9b}e\rf\nline two")).await;
        assert_eq!(pin.ok().flatten().as_deref().map(String::as_str), Some("a[2Jbcdef\nline two"));
    }

    #[tokio::test]
    async fn a_pinentry_that_never_answers_times_out() {
        let p = scripted("silent.sh", Duration::from_millis(200));
        assert_eq!(error_of(p.password("d", None).await).as_deref(), Some("the prompt timed out"));
        assert_eq!(error_of(p.confirm("d", true).await).as_deref(), Some("the prompt timed out"));
        assert_eq!(error_of(p.history("d").await).as_deref(), Some("the prompt timed out"));
    }

    #[test]
    fn one_line_replaces_line_breaks_and_controls() {
        assert_eq!(one_line("/usr/bin/git"), "/usr/bin/git");
        assert_eq!(
            one_line("a\nb\rc\td\u{1b}e\u{7f}f\u{9b}g\u{2028}h\u{2029}i"),
            "a\u{fffd}b\u{fffd}c\u{fffd}d\u{fffd}e\u{fffd}f\u{fffd}g\u{fffd}h\u{fffd}i"
        );
        assert_eq!(one_line("naïve ✓"), "naïve ✓");
    }

    /// Every character the review named, plus the rest of category Cf.
    const INVISIBLE: &[char] = &[
        '\u{ad}',
        '\u{61c}',
        '\u{200b}',
        '\u{200c}',
        '\u{200d}',
        '\u{200e}',
        '\u{200f}',
        '\u{202a}',
        '\u{202b}',
        '\u{202c}',
        '\u{202d}',
        '\u{202e}',
        '\u{2060}',
        '\u{2061}',
        '\u{2062}',
        '\u{2063}',
        '\u{2064}',
        '\u{2066}',
        '\u{2067}',
        '\u{2068}',
        '\u{2069}',
        '\u{feff}',
        '\u{2028}',
        '\u{2029}',
        '\u{600}',
        '\u{6dd}',
        '\u{180e}',
        '\u{206f}',
        '\u{fffb}',
        '\u{110bd}',
        '\u{e0001}',
        '\u{e007f}',
    ];

    #[test]
    fn one_line_replaces_bidi_and_other_invisible_format_characters() {
        for &c in INVISIBLE {
            assert_eq!(one_line(&format!("a{c}b")), "a\u{fffd}b", "U+{:04X}", u32::from(c));
            assert!(is_invisible(c), "U+{:04X}", u32::from(c));
        }
        for c in ['a', ' ', 'é', '\u{2010}', '\u{2070}', '\u{fffd}', '\u{e0080}'] {
            assert!(!is_invisible(c), "U+{:04X}", u32::from(c));
        }
    }

    #[test]
    fn escaping_round_trips() {
        let s = "50% off\nline two\r";
        assert_eq!(escape(s), "50%25 off%0Aline two%0D");
        assert_eq!(&*unescape(&escape(s)).unwrap(), s);
        assert_eq!(&*unescape("pa%25ss%").unwrap(), "pa%ss%");
        assert_eq!(&*unescape("%zz").unwrap(), "%zz");
    }

    #[test]
    fn a_percent_escape_at_the_very_end_is_decoded() {
        assert_eq!(&*unescape("%41").unwrap(), "A", "the whole string");
        assert_eq!(&*unescape("pin%25").unwrap(), "pin%");
        assert_eq!(&*unescape("line%0A").unwrap(), "line\n");
        assert_eq!(&*unescape("%4").unwrap(), "%4", "a truncated escape stays as sent");
    }

    #[test]
    fn only_hex_digits_form_a_percent_escape() {
        // from_str_radix would accept a sign.
        assert_eq!(&*unescape("%+5x").unwrap(), "%+5x");
        assert_eq!(&*unescape("%-1").unwrap(), "%-1");
    }

    #[test]
    fn only_cancel_and_not_confirmed_are_a_users_no() {
        assert!(is_users_no("83886179 Operation cancelled"));
        assert!(is_users_no("83886194 Not confirmed"));
        assert!(!is_users_no("83918950 Inappropriate ioctl for device"));
        assert!(!is_users_no("garbage"));
        assert!(!is_users_no("838861790 longer code"), "the whole code, not a prefix");
        assert!(!is_users_no("838861940"));
        assert!(is_users_no("83886179"));
    }
}
