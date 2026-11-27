use std::error::Error;
use std::io;
use std::sync::Arc;

use eframe::{CreationContext, egui};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, MouseButton, TrayIcon, TrayIconBuilder, TrayIconEvent};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows::Win32::UI::WindowsAndMessaging::{
    IsIconic, IsWindowVisible, PostMessageW, SIZE_MINIMIZED, SW_HIDE, SW_RESTORE, ShowWindow,
    ShowWindowAsync, WM_APP, WM_CLOSE, WM_NCDESTROY, WM_SIZE,
};

const MINIMIZE_SUBCLASS_ID: usize = 1;
const HIDE_MINIMIZED_WINDOW: u32 = WM_APP + 1;

pub(super) struct Tray {
    _icon: TrayIcon,
    window: HWND,
}

impl Drop for Tray {
    fn drop(&mut self) {
        // SAFETY: The app owns both the tray and window on the same UI thread.
        let _ =
            unsafe { RemoveWindowSubclass(self.window, Some(window_proc), MINIMIZE_SUBCLASS_ID) };
    }
}

pub(super) fn create(
    creation: &CreationContext<'_>,
    icon: &egui::IconData,
) -> Result<Tray, Box<dyn Error>> {
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
        .with_menu_on_left_click(false)
        .with_tooltip("Xiaomi Smart Scale S200")
        .with_icon(Icon::from_rgba(icon.rgba.clone(), icon.width, icon.height)?)
        .build()?;

    let hwnd = HWND(window_handle as *mut _);
    // SAFETY: Creation runs on the window's UI thread, and the callback borrows no Rust state.
    if !unsafe { SetWindowSubclass(hwnd, Some(window_proc), MINIMIZE_SUBCLASS_ID, 0) }.as_bool() {
        return Err(io::Error::other("Could not attach the Windows minimize handler.").into());
    }

    let context = creation.egui_ctx.clone();
    MenuEvent::set_event_handler(Some(Arc::new(move |event: MenuEvent| {
        if event.id == show_id {
            show_window(&context, window_handle);
        } else if event.id == quit_id {
            let hwnd = HWND(window_handle as *mut _);
            // SAFETY: The tray belongs to this window and only posts its standard close message.
            if unsafe { PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)) }.is_err() {
                context.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    })));
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
    Ok(Tray {
        _icon: tray,
        window: hwnd,
    })
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    subclass_id: usize,
    _reference_data: usize,
) -> LRESULT {
    // SAFETY: Windows invokes this callback with the live window and its message on the UI thread.
    unsafe {
        match message {
            WM_SIZE if wparam.0 == SIZE_MINIMIZED as usize => {
                // Let Windows finish minimizing before changing the window's visibility.
                let _ = PostMessageW(Some(hwnd), HIDE_MINIMIZED_WINDOW, WPARAM(0), LPARAM(0));
            }
            HIDE_MINIMIZED_WINDOW => {
                if IsIconic(hwnd).as_bool() && IsWindowVisible(hwnd).as_bool() {
                    let _ = ShowWindow(hwnd, SW_HIDE);
                }
                return LRESULT(0);
            }
            WM_NCDESTROY => {
                let _ = RemoveWindowSubclass(hwnd, Some(window_proc), subclass_id);
            }
            _ => {}
        }
        DefSubclassProc(hwnd, message, wparam, lparam)
    }
}

fn show_window(context: &egui::Context, window_handle: isize) {
    let hwnd = HWND(window_handle as *mut _);
    // SAFETY: The tray holds the handle of the app window it was created for.
    // Restoring it through Windows wakes the GUI even when egui hasn't painted while hidden.
    let _ = unsafe { ShowWindowAsync(hwnd, SW_RESTORE) };
    context.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    context.send_viewport_cmd(egui::ViewportCommand::Focus);
}
