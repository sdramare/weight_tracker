use std::collections::BTreeMap;
use std::io;
use std::ops::ControlFlow;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use xiaomi_s200::{
    BluetoothAddress, ConnectedWeightEvent, MODEL_NAME, SavedScaleLogins, Scale, ScaleBindKey,
    WeightReading, discover_scales, discover_scales_with_weight, listen_for_connected_weight,
};

const SCAN_DURATION: Duration = Duration::from_secs(30);
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

enum ScanStatus {
    Scanning(Receiver<ScanEvent>),
    Complete,
    Failed(String),
}

enum ScanEvent {
    Scale(Scale),
    Connecting,
    Weight(BluetoothAddress, ConnectedWeightEvent),
    Finished(io::Result<()>),
}

struct ScaleApp {
    scales: BTreeMap<BluetoothAddress, Scale>,
    readings: BTreeMap<BluetoothAddress, WeightReading>,
    status: ScanStatus,
    weight_hint: Option<String>,
    weight_status: Option<&'static str>,
}

impl ScaleApp {
    fn new(context: &egui::Context) -> Self {
        let mut visuals = egui::Visuals::light();
        visuals.override_text_color = Some(INK);
        context.set_visuals(visuals);

        let mut app = Self {
            scales: BTreeMap::new(),
            readings: BTreeMap::new(),
            status: ScanStatus::Complete,
            weight_hint: None,
            weight_status: None,
        };
        app.start_scan(context);
        app
    }

    fn start_scan(&mut self, context: &egui::Context) {
        let (sender, receiver) = mpsc::channel();
        let context = context.clone();
        self.scales.clear();
        self.readings.clear();
        self.weight_status = None;
        let logins = SavedScaleLogins::load_default();
        let bind_key = ScaleBindKey::from_environment();
        self.weight_hint = match (&logins, &bind_key) {
            (Ok(logins), _) if !logins.is_empty() => None,
            (_, Ok(Some(_))) => None,
            (Err(error), _) | (_, Err(error)) => Some(error.to_string()),
            _ => Some("Register your S200 to show live weight.".into()),
        };
        let logins = logins.unwrap_or_default();
        let bind_key = bind_key.ok().flatten();
        let worker = thread::Builder::new()
            .name("s200-discovery".into())
            .spawn(move || {
                let mut target = None;
                let on_scale = |scale: &Scale| {
                    if sender.send(ScanEvent::Scale(scale.clone())).is_err() {
                        return ControlFlow::Break(());
                    }
                    context.request_repaint();
                    if scale.is_connectable() && logins.token_for(scale).is_some() {
                        target = Some(scale.clone());
                        return ControlFlow::Break(());
                    }
                    ControlFlow::Continue(())
                };
                let result = match bind_key {
                    Some(key) => discover_scales_with_weight(SCAN_DURATION, &key, on_scale),
                    None => discover_scales(SCAN_DURATION, on_scale),
                };
                let result = result.and_then(|()| {
                    if let Some(scale) = target
                        && let Some(token) = logins.token_for(&scale)
                    {
                        if sender.send(ScanEvent::Connecting).is_err() {
                            return Ok(());
                        }
                        context.request_repaint();
                        return listen_for_connected_weight(
                            &scale,
                            token,
                            SCAN_DURATION,
                            |event| {
                                if sender
                                    .send(ScanEvent::Weight(scale.address(), event))
                                    .is_err()
                                {
                                    return ControlFlow::Break(());
                                }
                                context.request_repaint();
                                ControlFlow::Continue(())
                            },
                        );
                    }
                    Ok(())
                });
                let _ = sender.send(ScanEvent::Finished(result));
                context.request_repaint();
            });
        self.status = match worker {
            Ok(_) => ScanStatus::Scanning(receiver),
            Err(error) => {
                ScanStatus::Failed(format!("Could not start Bluetooth discovery. {error}"))
            }
        };
    }

    fn receive_scales(&mut self) {
        let ScanStatus::Scanning(receiver) = &self.status else {
            return;
        };
        loop {
            match receiver.try_recv() {
                Ok(ScanEvent::Scale(scale)) => {
                    self.scales.insert(scale.address(), scale);
                }
                Ok(ScanEvent::Connecting) => {
                    self.weight_status = Some("Connecting to the S200 with its saved login token…");
                }
                Ok(ScanEvent::Weight(_, ConnectedWeightEvent::Ready)) => {
                    self.weight_status = Some("Connected. Step on the S200 and hold still.");
                }
                Ok(ScanEvent::Weight(address, ConnectedWeightEvent::Reading(reading))) => {
                    self.readings.insert(address, reading);
                }
                Ok(ScanEvent::Finished(result)) => {
                    self.status = match result {
                        Ok(()) => ScanStatus::Complete,
                        Err(error) => ScanStatus::Failed(error.to_string()),
                    };
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.status =
                        ScanStatus::Failed("Bluetooth discovery ended unexpectedly.".into());
                    break;
                }
            }
        }
    }

    fn status_line(&self, ui: &mut egui::Ui) {
        match &self.status {
            ScanStatus::Scanning(_) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        self.weight_status
                            .unwrap_or("Scanning for 30 seconds. Tap the scale to wake it."),
                    );
                });
            }
            ScanStatus::Complete if self.scales.is_empty() => {
                ui.label("No scales found. Wake the scale and scan again.");
            }
            ScanStatus::Complete => {
                let count = self.scales.len();
                let label = if count == 1 { "scale" } else { "scales" };
                ui.label(format!("Scan complete. {count} {label} found."));
                if self.weight_hint.is_none()
                    && self.readings.is_empty()
                    && self.scales.values().all(|scale| scale.weight().is_none())
                {
                    ui.label("No matching registered scale or authenticated weight arrived.");
                }
            }
            ScanStatus::Failed(message) => {
                ui.label(RichText::new(format!("Bluetooth: {message}")).color(Color32::DARK_RED));
            }
        }
    }
}

impl eframe::App for ScaleApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive_scales();
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BACKGROUND).inner_margin(24))
            .show(context, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.heading(RichText::new("Nearby scales").size(28.0));
                        ui.label(RichText::new(MODEL_NAME.to_string()).color(MUTED));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let scanning = matches!(self.status, ScanStatus::Scanning(_));
                        let button =
                            egui::Button::new(RichText::new("Scan again").color(Color32::WHITE))
                                .fill(ACCENT)
                                .min_size(egui::vec2(100.0, 34.0));
                        if ui.add_enabled(!scanning, button).clicked() {
                            self.start_scan(context);
                        }
                    });
                });
                ui.add_space(15.0);
                self.status_line(ui);
                if let Some(hint) = &self.weight_hint {
                    ui.label(RichText::new(hint).color(MUTED));
                }
                ui.add_space(12.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for scale in self.scales.values() {
                        scale_row(ui, scale, self.readings.get(&scale.address()).copied());
                        ui.add_space(6.0);
                    }
                });
            });
    }
}

fn scale_row(ui: &mut egui::Ui, scale: &Scale, reading: Option<WeightReading>) {
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
                    if let Some(reading) =
                        reading.or_else(|| scale.weight().map(WeightReading::Settled))
                    {
                        let (label, weight) = match reading {
                            WeightReading::Live(weight) => ("Live weight", weight),
                            WeightReading::Settled(weight) => ("Settled weight", weight),
                        };
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
