use std::collections::BTreeMap;
use std::io;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use xiaomi_s200::{
    BluetoothAddress, ConnectedWeightEvent, MODEL_NAME, RegisteredScale, RegistrationEvent,
    RegistrationObserver, SavedScaleLogins, Scale, ScaleBindKey, ScaleScanObserver,
    ScaleSetupInteraction, Weight, WeightReading, WeightSessionObserver, XiaomiSignInLink,
    default_registration_directory, register_scale_europe, watch_connected_weights, watch_scales,
};

use super::history::{HistoryMonitor, WeightEntry};
use super::scale_setup::{SetupDialog, SetupRequest, SetupUpdate};
use super::{tray, weight_plot};

const RETRY_DELAY: Duration = Duration::from_secs(2);
const RECONNECT_QUIET_PERIOD: Duration = Duration::from_secs(5);
const HISTORY_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const SETUP_SCAN_TIME: Duration = Duration::from_secs(30);
const BACKGROUND: Color32 = Color32::from_rgb(244, 247, 243);
const INK: Color32 = Color32::from_rgb(19, 43, 38);
const MUTED: Color32 = Color32::from_rgb(69, 93, 84);
const ACCENT: Color32 = Color32::from_rgb(17, 102, 80);
const BORDER: Color32 = Color32::from_rgb(214, 224, 217);

pub fn run() -> eframe::Result {
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/scale-icon.png")).ok();
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([780.0, 640.0])
        .with_min_inner_size([540.0, 520.0]);
    if let Some(icon) = &icon {
        viewport = viewport.with_icon(icon.clone());
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "Xiaomi Smart Scale S200",
        options,
        Box::new(move |creation| Ok(Box::new(ScaleApp::new(creation, icon.as_ref())))),
    )
}

enum MonitorStatus {
    Listening,
    Connecting,
    Connected,
    SettingUp,
    Retrying(String),
    Stopped(String),
}

enum MonitorEvent {
    Scale(Scale),
    Status(MonitorStatus),
    Weight(BluetoothAddress, WeightReading),
    HistoryLoaded(Vec<WeightEntry>),
    HistoryError(Option<String>),
    WeightHints(Vec<String>),
    Setup(SetupUpdate),
}

struct ScaleRow {
    scale: Scale,
    live: Option<Weight>,
    settled: Option<Weight>,
}

struct ScaleApp {
    scales: BTreeMap<BluetoothAddress, ScaleRow>,
    events: Option<Receiver<MonitorEvent>>,
    setup_requests: Sender<SetupRequest>,
    setup_dialog: Option<SetupDialog>,
    listening: Arc<AtomicBool>,
    status: MonitorStatus,
    weight_hints: Vec<String>,
    history: Vec<WeightEntry>,
    history_error: Option<String>,
    group_by: weight_plot::GroupBy,
    _tray: Option<tray::Tray>,
    tray_error: Option<String>,
}

impl ScaleApp {
    fn new(creation: &eframe::CreationContext<'_>, icon: Option<&egui::IconData>) -> Self {
        let context = &creation.egui_ctx;
        let mut visuals = egui::Visuals::light();
        visuals.override_text_color = Some(INK);
        context.set_visuals(visuals);
        let (tray, tray_error) = match icon.map(|icon| tray::create(creation, icon)) {
            Some(Ok(tray)) => (Some(tray), None),
            Some(Err(error)) => (None, Some(error.to_string())),
            None => (None, Some("The scale icon could not be loaded.".into())),
        };

        let (sender, receiver) = mpsc::channel();
        let (setup_requests, setup_commands) = mpsc::channel();
        let listening = Arc::new(AtomicBool::new(true));
        let worker_listening = Arc::clone(&listening);
        let context = context.clone();
        let worker = thread::Builder::new()
            .name("s200-monitor".into())
            .spawn(move || {
                monitor_scales(setup_commands, &worker_listening, &sender, &context);
            });
        let (events, status) = match worker {
            Ok(_) => (Some(receiver), MonitorStatus::Listening),
            Err(error) => (None, MonitorStatus::Stopped(error.to_string())),
        };
        Self {
            scales: BTreeMap::new(),
            events,
            setup_requests,
            setup_dialog: None,
            listening,
            status,
            weight_hints: Vec::new(),
            history: Vec::new(),
            history_error: None,
            group_by: weight_plot::GroupBy::Day,
            _tray: tray,
            tray_error,
        }
    }

    fn receive_events(&mut self) {
        let Some(receiver) = &self.events else {
            return;
        };
        loop {
            match receiver.try_recv() {
                Ok(MonitorEvent::Scale(scale)) => {
                    let weight = scale.weight();
                    if let Some(row) = self.scales.get_mut(&scale.address()) {
                        row.settled = weight.or(row.settled);
                        row.scale = scale;
                    } else {
                        self.scales.insert(
                            scale.address(),
                            ScaleRow {
                                scale,
                                live: None,
                                settled: weight,
                            },
                        );
                    }
                }
                Ok(MonitorEvent::Status(status)) => {
                    if matches!(
                        status,
                        MonitorStatus::Listening
                            | MonitorStatus::SettingUp
                            | MonitorStatus::Retrying(_)
                    ) {
                        for row in self.scales.values_mut() {
                            row.live = None;
                        }
                    }
                    self.status = status;
                }
                Ok(MonitorEvent::Weight(address, reading)) => {
                    if let Some(row) = self.scales.get_mut(&address) {
                        match reading {
                            WeightReading::Live(weight) => row.live = Some(weight),
                            WeightReading::Settled(weight) => {
                                row.live = None;
                                row.settled = Some(weight);
                            }
                        }
                    }
                }
                Ok(MonitorEvent::HistoryLoaded(entries)) => {
                    self.history = entries;
                    self.history_error = None;
                }
                Ok(MonitorEvent::HistoryError(error)) => self.history_error = error,
                Ok(MonitorEvent::WeightHints(hints)) => self.weight_hints = hints,
                Ok(MonitorEvent::Setup(update)) => {
                    if let Some(dialog) = &mut self.setup_dialog {
                        dialog.receive(update);
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.events = None;
                    self.status =
                        MonitorStatus::Stopped("Bluetooth monitoring ended unexpectedly.".into());
                    if let Some(dialog @ SetupDialog::Running(_)) = &mut self.setup_dialog {
                        *dialog = SetupDialog::Finished(Err(io::Error::other(
                            "The Bluetooth worker stopped during setup.",
                        )));
                    }
                    break;
                }
            }
        }
    }

    fn status_line(&self, ui: &mut egui::Ui) {
        match &self.status {
            MonitorStatus::Listening => {
                ui.label("Listening for the scale. Step on to weigh.");
            }
            MonitorStatus::Connecting => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Connecting to the scale…");
                });
            }
            MonitorStatus::Connected => {
                ui.label("Connected. Step on and hold still for a reading.");
            }
            MonitorStatus::SettingUp => {
                ui.label("Setting up an S200. Weight monitoring is paused.");
            }
            MonitorStatus::Retrying(message) => {
                ui.label(RichText::new(format!("Bluetooth retrying. {message}")).color(MUTED));
            }
            MonitorStatus::Stopped(message) => {
                ui.label(RichText::new(format!("Bluetooth: {message}")).color(Color32::DARK_RED));
            }
        }
    }
}

impl Drop for ScaleApp {
    fn drop(&mut self) {
        self.listening.store(false, Ordering::Relaxed);
    }
}

fn monitor_credentials() -> (SavedScaleLogins, Option<ScaleBindKey>, Vec<String>) {
    let logins = SavedScaleLogins::load_default();
    let mut hints = match &logins {
        Ok(logins) => logins
            .warnings()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        Err(error) => vec![error.to_string()],
    };
    let logins = logins.unwrap_or_default();
    let bind_key = ScaleBindKey::from_environment();
    if let Err(error) = &bind_key {
        hints.push(error.to_string());
    }
    let bind_key = bind_key.ok().flatten();
    if logins.is_empty() && bind_key.is_none() {
        hints.push("Set up a scale to show live weight.".into());
    }
    (logins, bind_key, hints)
}

fn monitor_scales(
    setup_commands: Receiver<SetupRequest>,
    listening: &AtomicBool,
    sender: &Sender<MonitorEvent>,
    context: &egui::Context,
) {
    ScaleMonitor {
        setup_commands,
        listening,
        sender,
        context,
        history: HistoryMonitor::default(),
        next_history_refresh: Instant::now(),
        history_error: None,
        pending_setup: None,
        reconnect_guards: BTreeMap::new(),
    }
    .run();
}

struct ScaleMonitor<'a> {
    setup_commands: Receiver<SetupRequest>,
    listening: &'a AtomicBool,
    sender: &'a Sender<MonitorEvent>,
    context: &'a egui::Context,
    history: HistoryMonitor,
    next_history_refresh: Instant,
    history_error: Option<String>,
    pending_setup: Option<SetupRequest>,
    reconnect_guards: BTreeMap<BluetoothAddress, ReconnectGuard>,
}

impl ScaleMonitor<'_> {
    fn run(&mut self) {
        let (mut logins, mut bind_key, hints) = monitor_credentials();
        if self.post(MonitorEvent::WeightHints(hints)).is_break() {
            return;
        }
        while self.keep_running() {
            if let Some(request) = self
                .pending_setup
                .take()
                .or_else(|| self.setup_commands.try_recv().ok())
            {
                if self
                    .post(MonitorEvent::Status(MonitorStatus::SettingUp))
                    .is_break()
                {
                    return;
                }
                let result = self.register_scale(request);
                let hints;
                (logins, bind_key, hints) = monitor_credentials();
                if self.post(MonitorEvent::WeightHints(hints)).is_break()
                    || self
                        .post(MonitorEvent::Setup(SetupUpdate::Finished(result)))
                        .is_break()
                {
                    return;
                }
                continue;
            }
            if self
                .post(MonitorEvent::Status(MonitorStatus::Listening))
                .is_break()
            {
                return;
            }
            if let Err(error) = self.monitor_weight(&logins, bind_key.as_ref()) {
                if self.pending_setup.is_some() {
                    continue;
                }
                if !self.keep_running()
                    || self
                        .post(MonitorEvent::Status(MonitorStatus::Retrying(
                            error.to_string(),
                        )))
                        .is_break()
                {
                    return;
                }
                self.pending_setup = self.setup_commands.recv_timeout(RETRY_DELAY).ok();
            }
        }
    }

    fn monitor_weight(
        &mut self,
        logins: &SavedScaleLogins,
        bind_key: Option<&ScaleBindKey>,
    ) -> io::Result<()> {
        let scan_started_at = Instant::now();
        for guard in self.reconnect_guards.values_mut() {
            guard.scan_resumed(scan_started_at);
        }
        let mut scan = DesktopScaleScan {
            monitor: self,
            logins,
            target: None,
        };
        watch_scales(bind_key, &mut scan)?;
        if let Some(scale) = scan.target
            && let Some(token) = logins.token_for(&scale)
            && self.keep_monitoring()
            && self
                .post(MonitorEvent::Status(MonitorStatus::Connecting))
                .is_continue()
        {
            self.reconnect_guards.insert(
                scale.address(),
                ReconnectGuard {
                    last_offer: Instant::now(),
                },
            );
            let mut session = DesktopWeightSession {
                monitor: self,
                address: scale.address(),
            };
            watch_connected_weights(&scale, token, &mut session)?;
        }
        Ok(())
    }

    fn register_scale(&mut self, request: SetupRequest) -> io::Result<RegisteredScale> {
        let directory = default_registration_directory()?;
        let mut setup = DesktopRegistration {
            monitor: self,
            request,
        };
        register_scale_europe(SETUP_SCAN_TIME, &directory, &mut setup)
    }

    fn post(&self, event: MonitorEvent) -> ControlFlow<()> {
        if self.sender.send(event).is_err() {
            return ControlFlow::Break(());
        }
        self.context.request_repaint();
        ControlFlow::Continue(())
    }

    fn report_history(&mut self, result: io::Result<Option<Vec<WeightEntry>>>) -> ControlFlow<()> {
        match result {
            Ok(Some(entries)) => {
                self.history_error = None;
                self.post(MonitorEvent::HistoryLoaded(entries))
            }
            Ok(None) if self.history_error.take().is_some() => {
                self.post(MonitorEvent::HistoryError(None))
            }
            Ok(None) => ControlFlow::Continue(()),
            Err(error) => {
                let error = error.to_string();
                if self.history_error.as_ref() == Some(&error) {
                    return ControlFlow::Continue(());
                }
                self.history_error = Some(error.clone());
                self.post(MonitorEvent::HistoryError(Some(error)))
            }
        }
    }

    fn record_weight(&mut self, weight: Weight) -> ControlFlow<()> {
        let result = self.history.record(weight);
        self.report_history(result)
    }

    fn keep_running(&mut self) -> bool {
        if !self.listening.load(Ordering::Relaxed) {
            return false;
        }
        let now = Instant::now();
        if now < self.next_history_refresh {
            return true;
        }
        self.next_history_refresh = now + HISTORY_REFRESH_INTERVAL;
        let result = self.history.refresh();
        self.report_history(result).is_continue()
    }

    fn keep_monitoring(&mut self) -> bool {
        if self.pending_setup.is_none() {
            self.pending_setup = self.setup_commands.try_recv().ok();
        }
        self.pending_setup.is_none() && self.keep_running()
    }
}

struct ReconnectGuard {
    last_offer: Instant,
}

impl ReconnectGuard {
    fn scan_resumed(&mut self, now: Instant) {
        // Time spent connected, waiting to retry, or setting up gives no evidence of radio silence.
        self.last_offer = now;
    }

    fn connection_offered(&mut self, received_at: Instant) -> bool {
        let quiet =
            received_at.saturating_duration_since(self.last_offer) >= RECONNECT_QUIET_PERIOD;
        self.last_offer = self.last_offer.max(received_at);
        quiet
    }
}

struct DesktopScaleScan<'a, 'worker> {
    monitor: &'a mut ScaleMonitor<'worker>,
    logins: &'a SavedScaleLogins,
    target: Option<Scale>,
}

impl ScaleScanObserver for DesktopScaleScan<'_, '_> {
    fn should_scan(&mut self) -> bool {
        self.monitor.keep_monitoring()
    }

    fn scale_discovered(
        &mut self,
        scale: &Scale,
        broadcast_weight: Option<Weight>,
    ) -> ControlFlow<()> {
        self.monitor.post(MonitorEvent::Scale(scale.clone()))?;
        if let Some(weight) = broadcast_weight {
            self.monitor.record_weight(weight)?;
        }
        ControlFlow::Continue(())
    }

    fn connection_offered(&mut self, scale: &Scale, received_at: Instant) -> ControlFlow<()> {
        let address = scale.address();
        if let Some(guard) = self.monitor.reconnect_guards.get_mut(&address) {
            if !guard.connection_offered(received_at) {
                return ControlFlow::Continue(());
            }
            self.monitor.reconnect_guards.remove(&address);
        }
        if self.logins.token_for(scale).is_some() {
            self.target = Some(scale.clone());
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

struct DesktopWeightSession<'a, 'worker> {
    monitor: &'a mut ScaleMonitor<'worker>,
    address: BluetoothAddress,
}

impl WeightSessionObserver for DesktopWeightSession<'_, '_> {
    fn should_read_weight(&mut self) -> bool {
        self.monitor.keep_monitoring()
    }

    fn on_weight_event(&mut self, event: ConnectedWeightEvent) -> ControlFlow<()> {
        match event {
            ConnectedWeightEvent::Ready => self
                .monitor
                .post(MonitorEvent::Status(MonitorStatus::Connected)),
            ConnectedWeightEvent::Reading(reading) => {
                self.monitor
                    .post(MonitorEvent::Weight(self.address, reading))?;
                if let WeightReading::Settled(weight) = reading {
                    self.monitor.record_weight(weight)?;
                }
                ControlFlow::Continue(())
            }
        }
    }
}

struct DesktopRegistration<'a, 'worker> {
    monitor: &'a mut ScaleMonitor<'worker>,
    request: SetupRequest,
}

impl ScaleSetupInteraction for DesktopRegistration<'_, '_> {
    fn present_xiaomi_sign_in(&mut self, link: &XiaomiSignInLink) {
        let _ = self
            .monitor
            .post(MonitorEvent::Setup(SetupUpdate::SignInLink(
                link.to_string(),
            )));
    }

    fn setup_cancelled(&mut self) -> bool {
        self.request.is_cancelled() || !self.monitor.keep_running()
    }
}

impl RegistrationObserver for DesktopRegistration<'_, '_> {
    fn report_registration(&mut self, event: RegistrationEvent<'_>) {
        if let RegistrationEvent::Started(step) = event {
            let _ = self
                .monitor
                .post(MonitorEvent::Setup(SetupUpdate::Step(step)));
        }
    }
}

impl eframe::App for ScaleApp {
    fn logic(&mut self, _context: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive_events();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BACKGROUND).inner_margin(24))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(RichText::new("Weight monitor").size(28.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let button = egui::Button::new("Set up scale");
                        if ui
                            .add_enabled(self.setup_dialog.is_none(), button)
                            .clicked()
                        {
                            self.setup_dialog = Some(SetupDialog::start(&self.setup_requests));
                        }
                    });
                });
                ui.label(RichText::new(MODEL_NAME.to_string()).color(MUTED));
                ui.add_space(15.0);
                self.status_line(ui);
                for hint in &self.weight_hints {
                    ui.label(RichText::new(hint).color(MUTED));
                }
                if let Some(error) = &self.tray_error {
                    ui.label(
                        RichText::new(format!("System tray unavailable. {error}")).color(MUTED),
                    );
                }
                ui.add_space(12.0);
                egui::ScrollArea::vertical()
                    .max_height(142.0)
                    .show(ui, |ui| {
                        for row in self.scales.values() {
                            scale_row(ui, row);
                            ui.add_space(6.0);
                        }
                    });
                ui.add_space(12.0);
                egui::Frame::new()
                    .fill(Color32::WHITE)
                    .stroke(egui::Stroke::new(1.0_f32, BORDER))
                    .corner_radius(10)
                    .inner_margin(14)
                    .show(ui, |ui| {
                        if let Some(error) = &self.history_error {
                            ui.label(
                                RichText::new(format!("Weight history: {error}"))
                                    .color(Color32::DARK_RED),
                            );
                        }
                        weight_plot::show(ui, &self.history, &mut self.group_by);
                    });
            });
        if let Some(dialog) = &mut self.setup_dialog
            && dialog.show(ui.ctx())
        {
            self.setup_dialog = None;
        }
    }
}

fn scale_row(ui: &mut egui::Ui, row: &ScaleRow) {
    let scale = &row.scale;
    egui::Frame::new()
        .fill(Color32::WHITE)
        .stroke(egui::Stroke::new(1.0_f32, BORDER))
        .corner_radius(10)
        .inner_margin(12)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new(scale.name().to_string()).strong());
                    ui.label(
                        RichText::new(scale.address().to_string())
                            .monospace()
                            .color(MUTED),
                    );
                    let reading = row
                        .live
                        .map(|weight| ("Live weight", weight))
                        .or_else(|| row.settled.map(|weight| ("Last settled weight", weight)));
                    if let Some((label, weight)) = reading {
                        ui.label(
                            RichText::new(format!("{label}  {weight}"))
                                .strong()
                                .size(19.0)
                                .color(ACCENT),
                        );
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new(scale.signal_strength().to_string()).strong());
                        let state = if scale.is_connectable() {
                            "Connectable"
                        } else {
                            "Broadcasting"
                        };
                        ui.label(RichText::new(state).color(MUTED));
                    });
                });
            });
        });
}

#[cfg(test)]
mod reconnect_tests {
    use std::time::{Duration, Instant};

    use super::{RECONNECT_QUIET_PERIOD, ReconnectGuard};

    #[test]
    fn repeated_offers_do_not_reconnect_until_the_scale_goes_quiet() {
        let start = Instant::now();
        let mut guard = ReconnectGuard { last_offer: start };
        for seconds in 1..=30 {
            assert!(!guard.connection_offered(start + Duration::from_secs(seconds)));
        }
        let last_offer = start + Duration::from_secs(30);
        assert!(guard.connection_offered(last_offer + RECONNECT_QUIET_PERIOD));
    }

    #[test]
    fn an_unobserved_gap_during_a_connection_or_retry_does_not_rearm_the_scale() {
        let start = Instant::now();
        let mut guard = ReconnectGuard { last_offer: start };
        let resumed_at = start + Duration::from_secs(30);
        guard.scan_resumed(resumed_at);
        assert!(!guard.connection_offered(resumed_at));
        assert!(guard.connection_offered(resumed_at + RECONNECT_QUIET_PERIOD));
    }
}
