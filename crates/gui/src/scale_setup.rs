use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;

use eframe::egui;
use xiaomi_s200::{RegisteredScale, RegistrationStep};

pub(super) struct SetupRequest(Arc<AtomicBool>);

impl SetupRequest {
    pub(super) fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

pub(super) enum SetupUpdate {
    Step(RegistrationStep),
    SignInLink(String),
    Finished(io::Result<RegisteredScale>),
}

pub(super) enum SetupDialog {
    Running(SetupAttempt),
    Finished(io::Result<RegisteredScale>),
}

pub(super) struct SetupAttempt {
    cancelled: Arc<AtomicBool>,
    step: Option<RegistrationStep>,
    sign_in_link: Option<String>,
}

impl SetupDialog {
    pub(super) fn start(commands: &Sender<SetupRequest>) -> Self {
        let cancelled = Arc::new(AtomicBool::new(false));
        if commands.send(SetupRequest(Arc::clone(&cancelled))).is_err() {
            return Self::Finished(Err(io::Error::other(
                "The Bluetooth worker is unavailable.",
            )));
        }
        Self::Running(SetupAttempt {
            cancelled,
            step: None,
            sign_in_link: None,
        })
    }

    pub(super) fn receive(&mut self, update: SetupUpdate) {
        match (self, update) {
            (Self::Running(attempt), SetupUpdate::Step(step)) => {
                attempt.step = Some(step);
                if step != RegistrationStep::BrowserSignIn {
                    attempt.sign_in_link = None;
                }
            }
            (Self::Running(attempt), SetupUpdate::SignInLink(link)) => {
                attempt.sign_in_link = Some(link);
            }
            (dialog, SetupUpdate::Finished(result)) => *dialog = Self::Finished(result),
            _ => {}
        }
    }

    /// Returns whether the dialog should close.
    pub(super) fn show(&mut self, context: &egui::Context) -> bool {
        let modal = egui::Modal::new(egui::Id::unique("s200-scale-setup")).show(context, |ui| {
            ui.set_width(380.0);
            ui.heading("Set up scale");
            ui.add_space(8.0);
            match self {
                Self::Running(attempt) => {
                    attempt.show(ui);
                    false
                }
                Self::Finished(result) => {
                    match result {
                        Ok(scale) => {
                            ui.label(format!("Setup complete for {}.", scale.address()));
                            ui.label("Step on the scale to see your weight.");
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                            ui.label("Setup canceled.");
                        }
                        Err(error) => {
                            ui.strong("Couldn’t set up the scale");
                            ui.label(error.to_string());
                        }
                    }
                    ui.add_space(8.0);
                    ui.button("Close").clicked()
                }
            }
        });
        modal.inner || matches!(self, Self::Finished(_)) && modal.should_close()
    }
}

impl SetupAttempt {
    fn show(&self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.spinner();
            ui.label(self.status());
        });
        if self.cancelled.load(Ordering::Relaxed) {
            return;
        }
        if let Some(link) = &self.sign_in_link {
            ui.horizontal_wrapped(|ui| {
                if ui.button("Open Xiaomi sign-in").clicked() {
                    ui.ctx().open_url(egui::OpenUrl::new_tab(link.clone()));
                }
                if ui.button("Copy sign-in link").clicked() {
                    ui.ctx().copy_text(link.clone());
                }
            });
        }
        if matches!(
            self.step,
            None | Some(
                RegistrationStep::BrowserSignIn
                    | RegistrationStep::EuropeApi
                    | RegistrationStep::ScaleDiscovery
            )
        ) && ui.button("Cancel").clicked()
        {
            self.cancelled.store(true, Ordering::Relaxed);
        }
    }

    fn status(&self) -> &'static str {
        if self.cancelled.load(Ordering::Relaxed) {
            return "Canceling setup…";
        }
        match self.step {
            None => "Waiting for the Bluetooth monitor to pause…",
            Some(RegistrationStep::BrowserSignIn) if self.sign_in_link.is_some() => {
                "Sign in on Xiaomi’s website, then return here."
            }
            Some(RegistrationStep::BrowserSignIn) => "Requesting a Xiaomi sign-in link…",
            Some(RegistrationStep::EuropeApi) => "Checking your Xiaomi session…",
            Some(RegistrationStep::ScaleDiscovery) => {
                "Xiaomi sign-in is complete. Step on the S200 now to wake it. Keep it near this PC during the 30-second Bluetooth scan."
            }
            Some(RegistrationStep::BluetoothKeyExchange) => {
                "Connecting to the scale over Bluetooth…"
            }
            Some(RegistrationStep::AllocateDeviceId) => {
                "Registering the Bluetooth token with Xiaomi…"
            }
            Some(RegistrationStep::RequestCertificate) => {
                "Requesting Xiaomi’s signed setup authorization…"
            }
            Some(RegistrationStep::FinishSetup) => {
                "Sending authorization and waiting for the scale to confirm…"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;

    use eframe::egui::{self, Event, Shape};
    use xiaomi_s200::RegistrationStep;

    use super::{SetupDialog, SetupUpdate};

    #[test]
    fn progresses_through_sign_in_and_the_scale_scan() {
        let (commands, requests) = mpsc::channel();
        let mut dialog = SetupDialog::start(&commands);
        let request = requests.try_recv().unwrap();
        assert!(!request.0.load(Ordering::Relaxed));

        let context = egui::Context::default();
        let render = |dialog: &mut SetupDialog, events: Vec<Event>| {
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(780.0, 640.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ui| {
                    dialog.show(ui.ctx());
                },
            );
            output.textures_delta.clear();
            output
        };
        let button_position = |output: &egui::FullOutput, label: &str| {
            output
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    Shape::Text(text) if text.galley.text() == label => {
                        Some(text.pos + text.galley.size() / 2.0)
                    }
                    _ => None,
                })
                .unwrap()
        };
        let click = |dialog: &mut SetupDialog, pos| {
            let event = |pressed| Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            let _ = render(dialog, vec![Event::PointerMoved(pos), event(true)]);
            render(dialog, vec![event(false)])
        };
        dialog.receive(SetupUpdate::Step(RegistrationStep::BrowserSignIn));
        dialog.receive(SetupUpdate::SignInLink(
            "https://account.xiaomi.com/test".into(),
        ));
        let _ = render(&mut dialog, Vec::new());
        let sign_in = render(&mut dialog, Vec::new());
        let open = click(
            &mut dialog,
            button_position(&sign_in, "Open Xiaomi sign-in"),
        );
        assert!(open.platform_output.commands.iter().any(|command| {
            matches!(command, egui::OutputCommand::OpenUrl(url) if url.url == "https://account.xiaomi.com/test")
        }));

        dialog.receive(SetupUpdate::Step(RegistrationStep::ScaleDiscovery));
        let _ = render(&mut dialog, Vec::new());
        let scan = render(&mut dialog, Vec::new());
        assert!(scan.shapes.iter().any(
            |shape| matches!(&shape.shape, Shape::Text(text) if text.galley.text().contains("Step on"))
        ));
        assert!(!scan.shapes.iter().any(
            |shape| matches!(&shape.shape, Shape::Text(text) if text.galley.text() == "Open Xiaomi sign-in")
        ));
        let _ = click(&mut dialog, button_position(&scan, "Cancel"));
        assert!(request.0.load(Ordering::Relaxed));
        dialog.receive(SetupUpdate::Finished(
            Err(io::ErrorKind::Interrupted.into()),
        ));
        let cancelled = render(&mut dialog, Vec::new());
        assert!(cancelled.shapes.iter().any(
            |shape| matches!(&shape.shape, Shape::Text(text) if text.galley.text() == "Setup canceled.")
        ));
    }
}
