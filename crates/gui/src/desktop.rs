use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use xiaomi_s200::{
    BluetoothAddress, ConnectedWeightEvent, MODEL_NAME, SavedScaleLogins, Scale, ScaleBindKey,
    Weight, WeightReading, watch_connected_weights, watch_scales,
};

const RETRY_DELAY: Duration = Duration::from_secs(2);
const BACKGROUND: Color32 = Color32::from_rgb(244, 247, 243);
const INK: Color32 = Color32::from_rgb(19, 43, 38);
const MUTED: Color32 = Color32::from_rgb(69, 93, 84);
const ACCENT: Color32 = Color32::from_rgb(17, 102, 80);
const BORDER: Color32 = Color32::from_rgb(214, 224, 217);

pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([620.0, 430.0])
            .with_min_inner_size([430.0, 300.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Xiaomi Smart Scale S200",
        options,
        Box::new(|creation| Ok(Box::new(ScaleApp::new(&creation.egui_ctx)))),
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
    weight_hint: Option<String>,
}

impl ScaleApp {
    fn new(context: &egui::Context) -> Self {
        let mut visuals = egui::Visuals::light();
        visuals.override_text_color = Some(INK);
        context.set_visuals(visuals);

        let (sender, receiver) = mpsc::channel();
        let listening = Arc::new(AtomicBool::new(true));
        let logins = SavedScaleLogins::load_default();
        let bind_key = ScaleBindKey::from_environment();
        let weight_hint = match (&logins, &bind_key) {
            (Ok(logins), _) if !logins.is_empty() => None,
            (_, Ok(Some(_))) => None,
            (Err(error), _) | (_, Err(error)) => Some(error.to_string()),
            _ => Some("Register your S200 to show live weight.".into()),
        };
        let logins = logins.unwrap_or_default();
        let bind_key = bind_key.ok().flatten();
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
            weight_hint,
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
    let keep_listening = || listening.load(Ordering::Relaxed);
    let post = |event| {
        if sender.send(event).is_err() {
            return ControlFlow::Break(());
        }
        context.request_repaint();
        ControlFlow::Continue(())
    };
    while keep_listening() && post(MonitorEvent::Status(MonitorStatus::Listening)).is_continue() {
        let mut target = None;
        let result = watch_scales(bind_key, keep_listening, |scale| {
            post(MonitorEvent::Scale(scale.clone()))?;
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
                    let update = match event {
                        ConnectedWeightEvent::Ready => {
                            MonitorEvent::Status(MonitorStatus::Connected)
                        }
                        ConnectedWeightEvent::Reading(reading) => {
                            MonitorEvent::Weight(scale.address(), reading)
                        }
                    };
                    post(update)
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
                ui.heading(RichText::new("Nearby scales").size(28.0));
                ui.label(RichText::new(MODEL_NAME.to_string()).color(MUTED));
                ui.add_space(15.0);
                self.status_line(ui);
                if let Some(hint) = &self.weight_hint {
                    ui.label(RichText::new(hint).color(MUTED));
                }
                ui.add_space(12.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for row in self.scales.values() {
                        scale_row(ui, row);
                        ui.add_space(6.0);
                    }
                });
            });
    }
}

fn scale_row(ui: &mut egui::Ui, row: &ScaleRow) {
    let scale = &row.scale;
    egui::Frame::new()
        .fill(Color32::WHITE)
        .stroke(egui::Stroke::new(1.0, BORDER))
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
