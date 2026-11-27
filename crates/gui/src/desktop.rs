use std::cell::{Cell, RefCell};
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
    BluetoothAddress, ConnectedWeightEvent, MODEL_NAME, SavedScaleLogins, Scale, ScaleBindKey,
    Weight, WeightReading, watch_connected_weights, watch_scales,
};

use super::history::{HistoryMonitor, WeightEntry};
use super::{tray, weight_plot};

const RETRY_DELAY: Duration = Duration::from_secs(2);
const HISTORY_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
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
    Retrying(String),
    Stopped(String),
}

enum MonitorEvent {
    Scale(Scale),
    Status(MonitorStatus),
    Weight(BluetoothAddress, WeightReading),
    HistoryLoaded(Vec<WeightEntry>),
    HistoryError(Option<String>),
}

struct ScaleRow {
    scale: Scale,
    live: Option<Weight>,
    settled: Option<Weight>,
}

struct ScaleApp {
    scales: BTreeMap<BluetoothAddress, ScaleRow>,
    events: Option<Receiver<MonitorEvent>>,
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
        let listening = Arc::new(AtomicBool::new(true));
        let logins = SavedScaleLogins::load_default();
        let mut weight_hints = match &logins {
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
            weight_hints.push(error.to_string());
        }
        let bind_key = bind_key.ok().flatten();
        if logins.is_empty() && bind_key.is_none() {
            weight_hints.push("Register your S200 to show live weight.".into());
        }
        let worker_listening = Arc::clone(&listening);
        let context = context.clone();
        let worker = thread::Builder::new()
            .name("s200-monitor".into())
            .spawn(move || {
                monitor_scales(
                    &logins,
                    bind_key.as_ref(),
                    &worker_listening,
                    &sender,
                    &context,
                );
            });
        let (events, status) = match worker {
            Ok(_) => (Some(receiver), MonitorStatus::Listening),
            Err(error) => (None, MonitorStatus::Stopped(error.to_string())),
        };
        Self {
            scales: BTreeMap::new(),
            events,
            listening,
            status,
            weight_hints,
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
                        MonitorStatus::Listening | MonitorStatus::Retrying(_)
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
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.events = None;
                    self.status =
                        MonitorStatus::Stopped("Bluetooth monitoring ended unexpectedly.".into());
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

fn monitor_scales(
    logins: &SavedScaleLogins,
    bind_key: Option<&ScaleBindKey>,
    listening: &AtomicBool,
    sender: &Sender<MonitorEvent>,
    context: &egui::Context,
) {
    let post = |event| {
        if sender.send(event).is_err() {
            return ControlFlow::Break(());
        }
        context.request_repaint();
        ControlFlow::Continue(())
    };
    let history = RefCell::new(HistoryMonitor::default());
    let next_history_refresh = Cell::new(Instant::now());
    let history_error = RefCell::new(None);
    let report_history = |result: io::Result<Option<Vec<WeightEntry>>>| {
        let mut previous_error = history_error.borrow_mut();
        match result {
            Ok(Some(entries)) => {
                *previous_error = None;
                post(MonitorEvent::HistoryLoaded(entries))
            }
            Ok(None) if previous_error.take().is_some() => post(MonitorEvent::HistoryError(None)),
            Ok(None) => ControlFlow::Continue(()),
            Err(error) => {
                let error = error.to_string();
                if previous_error.as_ref() == Some(&error) {
                    return ControlFlow::Continue(());
                }
                *previous_error = Some(error.clone());
                post(MonitorEvent::HistoryError(Some(error)))
            }
        }
    };
    let keep_listening = || {
        if !listening.load(Ordering::Relaxed) {
            return false;
        }
        let now = Instant::now();
        if now < next_history_refresh.get() {
            return true;
        }
        next_history_refresh.set(now + HISTORY_REFRESH_INTERVAL);
        report_history(history.borrow_mut().refresh()).is_continue()
    };
    let record_weight = |weight| report_history(history.borrow_mut().record(weight));
    while keep_listening() && post(MonitorEvent::Status(MonitorStatus::Listening)).is_continue() {
        let mut target = None;
        let result =
            watch_scales(bind_key, keep_listening, |scale, broadcast_weight| {
                post(MonitorEvent::Scale(scale.clone()))?;
                if let Some(weight) = broadcast_weight {
                    record_weight(weight)?;
                }
                if scale.is_connectable() && logins.token_for(scale).is_some() {
                    target = Some(scale.clone());
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            })
            .and_then(|()| {
                if let Some(scale) = target
                    && let Some(token) = logins.token_for(&scale)
                    && post(MonitorEvent::Status(MonitorStatus::Connecting)).is_continue()
                {
                    return watch_connected_weights(&scale, token, keep_listening, |event| {
                        match event {
                            ConnectedWeightEvent::Ready => {
                                post(MonitorEvent::Status(MonitorStatus::Connected))
                            }
                            ConnectedWeightEvent::Reading(reading) => {
                                post(MonitorEvent::Weight(scale.address(), reading))?;
                                if let WeightReading::Settled(weight) = reading {
                                    record_weight(weight)?;
                                }
                                ControlFlow::Continue(())
                            }
                        }
                    });
                }
                Ok(())
            });
        if let Err(error) = result {
            if !keep_listening()
                || post(MonitorEvent::Status(MonitorStatus::Retrying(
                    error.to_string(),
                )))
                .is_break()
            {
                return;
            }
            thread::sleep(RETRY_DELAY);
        }
    }
}

impl eframe::App for ScaleApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive_events();
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BACKGROUND).inner_margin(24))
            .show(context, |ui| {
                ui.heading(RichText::new("Weight monitor").size(28.0));
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
