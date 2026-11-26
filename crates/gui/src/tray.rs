use std::error::Error;
use std::io;

use eframe::{CreationContext, egui};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, MouseButton, TrayIcon, TrayIconBuilder, TrayIconEvent};
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    PostMessageW, SW_RESTORE, ShowWindowAsync, WM_CLOSE,
};

pub(super) fn create(
    creation: &CreationContext<'_>,
    icon: &egui::IconData,
) -> Result<TrayIcon, Box<dyn Error>> {
    let RawWindowHandle::Win32(window) = creation.window_handle()?.as_raw() else {
        return Err(io::Error::other("the Windows tray requires a window handle").into());
    };
    let window_handle = window.hwnd.get();
    let menu = Menu::new();
    let show = MenuItem::new("Show weight window", true, None);
    let quit = MenuItem::new("Quit", true, None);
    menu.append_items(&[&show, &quit])?;
    let show_id = show.id().clone();
    let quit_id = quit.id().clone();
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Xiaomi Smart Scale S200")
        .with_icon(Icon::from_rgba(icon.rgba.clone(), icon.width, icon.height)?)
        .build()?;

    let context = creation.egui_ctx.clone();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        if event.id == show_id {
            show_window(&context, window_handle);
        } else if event.id == quit_id {
            let hwnd = HWND(window_handle as *mut _);
            // SAFETY: The tray belongs to this window and only posts its standard close message.
            if unsafe { PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)) }.is_err() {
                context.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }));
    let context = creation.egui_ctx.clone();
    let tray_id = tray.id().clone();
    TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
        if let TrayIconEvent::DoubleClick {
            id,
            button: MouseButton::Left,
            ..
        } = event
            && id == tray_id
        {
            show_window(&context, window_handle);
        }
    }));
    Ok(tray)
}

fn show_window(context: &egui::Context, window_handle: isize) {
    let hwnd = HWND(window_handle as *mut _);
    // SAFETY: The tray holds the handle of the app window it was created for.
    // Restoring it through Windows wakes the GUI even when egui hasn't painted while hidden.
    let _ = unsafe { ShowWindowAsync(hwnd, SW_RESTORE) };
    context.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    context.send_viewport_cmd(egui::ViewportCommand::Focus);
}
