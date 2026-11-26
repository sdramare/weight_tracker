use std::collections::BTreeMap;
use std::io;
use std::ops::ControlFlow;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use xiaomi_s200::{BluetoothAddress, MODEL_NAME, Scale, discover_scales};

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
        "Xiaomi Scale Discovery",
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
    Finished(io::Result<()>),
}

struct ScaleApp {
    scales: BTreeMap<BluetoothAddress, Scale>,
    status: ScanStatus,
}

impl ScaleApp {
    fn new(context: &egui::Context) -> Self {
        let mut visuals = egui::Visuals::light();
        visuals.override_text_color = Some(INK);
        context.set_visuals(visuals);

        let mut app = Self {
            scales: BTreeMap::new(),
            status: ScanStatus::Complete,
        };
        app.start_scan(context);
        app
    }

    fn start_scan(&mut self, context: &egui::Context) {
        let (sender, receiver) = mpsc::channel();
        let context = context.clone();
        self.scales.clear();
        let worker = thread::Builder::new()
            .name("s200-discovery".into())
            .spawn(move || {
                let result = discover_scales(SCAN_DURATION, |scale| {
                    if sender.send(ScanEvent::Scale(scale.clone())).is_err() {
                        return ControlFlow::Break(());
                    }
                    context.request_repaint();
                    ControlFlow::Continue(())
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
                    ui.label("Scanning for 30 seconds. Step on the scale to wake it.");
                });
            }
            ScanStatus::Complete if self.scales.is_empty() => {
                ui.label("No scales found. Wake the scale and scan again.");
            }
            ScanStatus::Complete => {
                let count = self.scales.len();
                let label = if count == 1 { "scale" } else { "scales" };
                ui.label(format!("Scan complete. {count} {label} found."));
            }
            ScanStatus::Failed(message) => {
                ui.label(
                    RichText::new(format!("Bluetooth scan stopped. {message}"))
                        .color(Color32::DARK_RED),
                );
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
                ui.add_space(12.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for scale in self.scales.values() {
                        scale_row(ui, scale);
                        ui.add_space(6.0);
                    }
                });
            });
    }
}

fn scale_row(ui: &mut egui::Ui, scale: &Scale) {
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
