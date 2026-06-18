use eff_wordlist::large::random_word;
use gtk::prelude::*;
use gtk::{
    Application, ApplicationWindow, Box as GtkBox, Button, DropDown, Entry, Expander, FileChooserAction,
    FileChooserNative, GestureClick, Label, ListBox, Orientation, PasswordEntry, ResponseType,
    ScrolledWindow, Window,
};
use gtk4 as gtk;
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

use crate::commands::daemon::{DaemonEvent, SyncResponse};

// Shared vault session state
pub struct VaultSession {
    pub file: File,
    pub metadata: crate::vfs::VaultMetadata,
    pub unlocked_vault: crate::crypto::UnlockedVault,
    pub current_offset: u64,
}

// Global queue for handling cross-thread Daemon events safely in GTK
static INCOMING_EVENTS: Mutex<Vec<DaemonEvent>> = Mutex::new(Vec::new());

// Initialize background daemon listener without blocking the main GTK thread
fn start_daemon_and_listener() {
    let (tokio_tx, mut tokio_rx) = tokio::sync::mpsc::channel(10);
    crate::commands::daemon::set_event_sender(tokio_tx);

    // Spawn the core Daemon in a dedicated standard thread
    std::thread::spawn(|| {
        if let Err(e) = crate::commands::daemon::handle_daemon() {
            eprintln!("[Daemon Error] {}", e);
        }
    });

    // Bridge Tokio events into the Mutex Queue
    std::thread::spawn(move || {
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            rt.block_on(async {
                while let Some(event) = tokio_rx.recv().await {
                    if let Ok(mut queue) = INCOMING_EVENTS.lock() {
                        queue.push(event);
                    }
                }
            });
        }
    });
}

pub fn run_gui() -> Result<(), Box<dyn std::error::Error>> {
    start_daemon_and_listener();

    let app = Application::builder()
        .application_id("org.atom.Vault")
        .build();

    app.connect_activate(build_login_ui);
    app.run();

    Ok(())
}

fn build_login_ui(app: &Application) {
    // Start polling the global Daemon Queue every 500ms safely
    gtk::glib::timeout_add_local(std::time::Duration::from_millis(500), move || {
        let mut events_to_process = Vec::new();
        if let Ok(mut queue) = INCOMING_EVENTS.lock() {
            std::mem::swap(&mut events_to_process, &mut *queue);
        }

        for event in events_to_process {
            match event {
                DaemonEvent::SyncRequest {
                    sender_nick,
                    filename,
                    response_channel,
                } => {
                    show_incoming_sync_dialog(sender_nick, filename, response_channel);
                }
                DaemonEvent::Log(msg) => {
                    println!("[Daemon Log] {}", msg);
                }
            }
        }
        gtk::glib::ControlFlow::Continue
    });

    let window = ApplicationWindow::builder()
        .application(app)
        .title("Atom Vault - Login")
        .default_width(450)
        .default_height(350)
        .build();

    let vbox = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(16)
        .margin_top(32)
        .margin_bottom(32)
        .margin_start(32)
        .margin_end(32)
        .build();

    let title = Label::builder()
        .label("<span size='xx-large' weight='bold'>Atom Vault</span>")
        .use_markup(true)
        .build();

    let selected_path: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));

    let select_btn = Button::builder().label("Select .aegis Vault").build();
    let pass_entry = PasswordEntry::builder()
        .placeholder_text("Master Password")
        .build();
    let unlock_btn = Button::builder()
        .label("Unlock Vault")
        .css_classes(["suggested-action"])
        .build();
    let create_btn = Button::builder()
        .label("Create New Vault")
        .css_classes(["flat"])
        .build();
    let status_label = Label::builder()
        .label("Please select or create a vault to begin.")
        .build();

    let path_clone = Rc::clone(&selected_path);
    let btn_clone = select_btn.clone();
    let status_clone = status_label.clone();
    let window_weak = window.downgrade();

    select_btn.connect_clicked(move |_| {
        let chooser = FileChooserNative::new(
            Some("Open .aegis Vault"),
            window_weak
                .upgrade()
                .as_ref()
                .map(|w| w.upcast_ref::<gtk::Window>()),
            FileChooserAction::Open,
            Some("_Open"),
            Some("_Cancel"),
        );

        let path_alloc = Rc::clone(&path_clone);
        let btn_alloc = btn_clone.clone();
        let status_alloc = status_clone.clone();

        chooser.connect_response(move |dialog, response| {
            if response == ResponseType::Accept {
                if let Some(file) = dialog.file() {
                    if let Some(path) = file.path() {
                        btn_alloc.set_label(&format!(
                            "Selected: {:?}",
                            path.file_name().unwrap_or_default()
                        ));
                        *path_alloc.borrow_mut() = Some(path);
                        status_alloc.set_label("Vault selected. Enter master password.");
                    }
                }
            }
            dialog.destroy();
        });

        chooser.show();
    });

    let path_clone2 = Rc::clone(&selected_path);
    let status_clone2 = status_label.clone();
    let pass_entry_clone = pass_entry.clone();
    let window_clone = window.clone();

    unlock_btn.connect_clicked(move |_| {
        let path_opt = path_clone2.borrow();
        let secure_password = Zeroizing::new(pass_entry_clone.text().to_string());

        pass_entry_clone.set_text("");

        if let Some(path) = &*path_opt {
            if secure_password.is_empty() {
                status_clone2.set_label("Error: Password cannot be empty!");
                return;
            }

            status_clone2.set_label("Decrypting...");

            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(mut file) => {
                    match crate::storage::load_vault_metadata(&mut file, &secure_password) {
                        Ok((metadata, unlocked_vault, current_offset)) => {
                            let session = Rc::new(RefCell::new(VaultSession {
                                file,
                                metadata,
                                unlocked_vault,
                                current_offset,
                            }));

                            let current_vault_path = path.to_string_lossy().to_string();
                            build_vault_explorer(&window_clone, session, current_vault_path);
                        }
                        Err(_) => {
                            status_clone2.set_label("Error: Invalid password or corrupted vault.");
                        }
                    }
                }
                Err(e) => {
                    status_clone2.set_label(&format!("Error: Could not open file: {}", e));
                }
            }
        } else {
            status_clone2.set_label("Error: Please select a vault first!");
        }
    });

    let create_window_weak = window.downgrade();
    create_btn.connect_clicked(move |_| {
        let chooser = FileChooserNative::new(
            Some("Select Destination Folder"),
            create_window_weak
                .upgrade()
                .as_ref()
                .map(|w| w.upcast_ref::<gtk::Window>()),
            FileChooserAction::SelectFolder,
            Some("_Select"),
            Some("_Cancel"),
        );

        let parent_window_clone = create_window_weak.upgrade().unwrap();

        chooser.connect_response(move |dialog, response| {
            if response == ResponseType::Accept {
                if let Some(file) = dialog.file() {
                    if let Some(folder_path) = file.path() {
                        show_create_vault_dialog(&parent_window_clone, folder_path);
                    }
                }
            }
            dialog.destroy();
        });
        chooser.show();
    });

    vbox.append(&title);
    vbox.append(&select_btn);
    vbox.append(&pass_entry);
    vbox.append(&unlock_btn);
    vbox.append(&create_btn);
    vbox.append(&status_label);

    window.set_child(Some(&vbox));
    window.present();
}

// UI HELPER: Modal for handling incoming P2P sync requests
fn show_incoming_sync_dialog(
    sender_nick: String,
    filename: String,
    response_channel: tokio::sync::oneshot::Sender<SyncResponse>,
) {
    let dialog = Window::builder()
        .title("Incoming P2P Sync Request")
        .default_width(380)
        .modal(true)
        .build();

    let vbox = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .margin_top(16)
        .margin_bottom(16)
        .margin_start(16)
        .margin_end(16)
        .build();

    let label = Label::builder()
        .label(&format!(
            "<b>{}</b> wants to sync <b>{}</b> with you over the P2P network.",
            sender_nick, filename
        ))
        .use_markup(true)
        .wrap(true)
        .build();

    let vault_label_entry = Entry::builder()
        .placeholder_text("Vault Label (e.g. Work)")
        .build();

    let mut default_path = dirs::home_dir().unwrap_or_default();
    default_path.push(format!("Downloads/{}/{}", sender_nick, filename));

    let path_entry = Entry::builder()
        .text(default_path.to_string_lossy().to_string())
        .build();

    let btn_box = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .build();
    let accept_btn = Button::builder()
        .label("Accept")
        .css_classes(["suggested-action"])
        .build();
    let reject_btn = Button::builder()
        .label("Reject")
        .css_classes(["destructive-action"])
        .build();

    btn_box.append(&accept_btn);
    btn_box.append(&reject_btn);

    vbox.append(&label);
    vbox.append(&gtk::Separator::builder().build());
    vbox.append(
        &Label::builder()
            .label("Assign local label:")
            .xalign(0.0)
            .build(),
    );
    vbox.append(&vault_label_entry);
    vbox.append(
        &Label::builder()
            .label("Destination path:")
            .xalign(0.0)
            .build(),
    );
    vbox.append(&path_entry);
    vbox.append(&btn_box);

    dialog.set_child(Some(&vbox));

    let dialog_clone_1 = dialog.clone();
    let dialog_clone_2 = dialog.clone();

    let resp_chan = Rc::new(RefCell::new(Some(response_channel)));
    let resp_chan_rej = Rc::clone(&resp_chan);

    accept_btn.connect_clicked(move |_| {
        if let Some(chan) = resp_chan.borrow_mut().take() {
            let v_label = vault_label_entry.text().to_string();
            let v_path = path_entry.text().to_string();

            let _ = chan.send(SyncResponse {
                accepted: true,
                label: Some(if v_label.is_empty() {
                    "Synced Vault".to_string()
                } else {
                    v_label
                }),
                save_path: Some(if v_path.is_empty() {
                    default_path.to_string_lossy().to_string()
                } else {
                    v_path
                }),
            });
        }
        dialog_clone_1.close();
    });

    reject_btn.connect_clicked(move |_| {
        if let Some(chan) = resp_chan_rej.borrow_mut().take() {
            let _ = chan.send(SyncResponse {
                accepted: false,
                label: None,
                save_path: None,
            });
        }
        dialog_clone_2.close();
    });

    dialog.present();
}

fn show_create_vault_dialog(parent: &ApplicationWindow, folder_path: PathBuf) {
    let dialog = Window::builder()
        .transient_for(parent)
        .modal(true)
        .title("Initialize Secure Vault")
        .default_width(380)
        .destroy_with_parent(true)
        .build();

    let vbox = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .margin_top(16)
        .margin_bottom(16)
        .margin_start(16)
        .margin_end(16)
        .build();

    let info_label = Label::builder()
        .label(&format!("Path: {}", folder_path.display()))
        .xalign(0.0)
        .build();
    let name_entry = Entry::builder()
        .placeholder_text("Vault Name (e.g., personal)")
        .build();

    // SADE VE MANTIKLI ŞİFRE KUTULARI (Göz ikonu kopyalamaya izin verir)
    let pass_entry = PasswordEntry::builder()
        .placeholder_text("Master Password")
        .show_peek_icon(true)
        .build();
    let pass_confirm = PasswordEntry::builder()
        .placeholder_text("Confirm Password")
        .show_peek_icon(true)
        .build();

    let gen_btn = Button::builder()
        .label("Generate Secure Passphrase")
        .build();

    let status_label = Label::builder().use_markup(true).build();

    // JENERATÖR BUTONU ETKİLEŞİMİ
    let pass_entry_gen = pass_entry.clone();
    let pass_confirm_gen = pass_confirm.clone();
    let status_gen = status_label.clone();

    gen_btn.connect_clicked(move |_| {
        let mut words = Vec::with_capacity(10);
        for _ in 0..10 {
            words.push(random_word());
        }
        let pass = words.join(" ");
        
        pass_entry_gen.set_text(&pass);
        pass_confirm_gen.set_text(&pass);
        
        status_gen.set_label("<span foreground='orange'><b>⚠️ Passphrase generated! Click the eye icon to view and copy.</b></span>");
    });

    // TÜM KRİPTOGRAFİ ÖZELLİKLERİNİ İÇEREN EXPANDER
    let advanced_expander = Expander::builder().label("Advanced Crypto Settings").build();
    let adv_box = GtkBox::builder().orientation(Orientation::Vertical).spacing(8).build();

    let kdf_label = Label::builder().label("Key Derivation Function:").xalign(0.0).build();
    let kdf_dropdown = DropDown::from_strings(&["Argon2id", "Scrypt"]);

    let time_label = Label::builder().label("Target Decryption Time (ms):").xalign(0.0).build();
    let time_entry = Entry::builder().text("1000").build();

    let memory_entry = Entry::builder().placeholder_text("Memory (KiB) [Optional]").build();
    let rounds_entry = Entry::builder().placeholder_text("Explicit Rounds [Optional]").build();
    let threads_entry = Entry::builder().placeholder_text("Parallelism (Threads) [Optional]").build();

    adv_box.append(&kdf_label);
    adv_box.append(&kdf_dropdown);
    adv_box.append(&time_label);
    adv_box.append(&time_entry);
    adv_box.append(&memory_entry);
    adv_box.append(&rounds_entry);
    adv_box.append(&threads_entry);
    
    advanced_expander.set_child(Some(&adv_box));

    let confirm_btn = Button::builder()
        .label("Create Vault")
        .css_classes(["suggested-action"])
        .build();

    vbox.append(&info_label);
    vbox.append(&name_entry);
    vbox.append(&pass_entry);
    vbox.append(&pass_confirm);
    vbox.append(&gen_btn);
    vbox.append(&advanced_expander);
    vbox.append(&confirm_btn);
    vbox.append(&status_label);

    dialog.set_child(Some(&vbox));

    let dialog_clone = dialog.clone();
    
    // Girdileri GTK buffer'ından izole etmek için cloneluyoruz
    let pass_entry_clone = pass_entry.clone();
    let pass_confirm_clone = pass_confirm.clone();
    let name_entry_clone = name_entry.clone();
    let kdf_dropdown_clone = kdf_dropdown.clone();
    let time_entry_clone = time_entry.clone();
    let memory_entry_clone = memory_entry.clone();
    let rounds_entry_clone = rounds_entry.clone();
    let threads_entry_clone = threads_entry.clone();

    confirm_btn.connect_clicked(move |_| {
        let name = name_entry_clone.text().to_string();
        
        let secure_pass = zeroize::Zeroizing::new(pass_entry_clone.text().to_string());
        let secure_confirm = zeroize::Zeroizing::new(pass_confirm_clone.text().to_string());

        // GTK Buffer Wipe (Zero-Trust Standardı)
        pass_entry_clone.set_text("");
        pass_confirm_clone.set_text("");

        if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains('\0') {
            status_label.set_label("<span foreground='red'>Invalid or empty vault name.</span>");
            return;
        }

        if secure_pass.is_empty() {
            status_label.set_label("<span foreground='red'>Password cannot be empty.</span>");
            return;
        }
        if *secure_pass != *secure_confirm {
            status_label.set_label("<span foreground='red'>Passwords do not match.</span>");
            return;
        }

        // Tuna'nın Tüm Parametrelerini Okuma (Eğer boş ise handle_create tarafındaki defaultları kullanacak)
        let kdf_choice = if kdf_dropdown_clone.selected() == 0 { "argon2id" } else { "scrypt" };
        let dec_time: u32 = time_entry_clone.text().parse().unwrap_or(1000);
        let mem_arg: Option<u32> = memory_entry_clone.text().parse().ok();
        let rounds_arg: Option<u32> = rounds_entry_clone.text().parse().ok();
        let threads_arg: Option<u32> = threads_entry_clone.text().parse().ok();

        status_label.set_label("Deriving keys, please wait...");

        match crate::commands::create::handle_create(
            &folder_path.to_string_lossy(),
            &name,
            kdf_choice,
            mem_arg,       
            rounds_arg,       
            threads_arg,       
            dec_time,   
            false,      
            Some(secure_pass),
        ) {
            Ok(_) => {
                dialog_clone.close();
            }
            Err(e) => {
                status_label.set_label(&format!("<span foreground='red'>Error: {}</span>", e));
            }
        }
    });

    dialog.present();
}

fn build_vault_explorer(
    window: &ApplicationWindow,
    session: Rc<RefCell<VaultSession>>,
    current_vault_path: String,
) {
    window.set_title(Some("Atom Vault - Secure Explorer"));
    window.set_default_width(750);
    window.set_default_height(550);

    let vbox = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(8)
        .build();

    let toolbar = GtkBox::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();

    let title = Label::builder()
        .label("<span size='large' weight='bold'>Encrypted File System</span>")
        .use_markup(true)
        .hexpand(true)
        .xalign(0.0)
        .build();

    let import_btn = Button::builder()
        .label("Import File")
        .css_classes(["suggested-action"])
        .build();
    let export_btn = Button::builder().label("Export File").build();
    let p2p_btn = Button::builder().label("P2P Network").build();
    let lock_btn = Button::builder()
        .label("Lock & Exit")
        .css_classes(["destructive-action"])
        .build();

    toolbar.append(&title);
    toolbar.append(&import_btn);
    toolbar.append(&export_btn);
    toolbar.append(&p2p_btn);
    toolbar.append(&lock_btn);

    let action_status_label = Label::builder()
        .use_markup(true)
        .margin_start(12)
        .margin_end(12)
        .xalign(0.0)
        .build();

    let list_box = ListBox::builder()
        .selection_mode(gtk::SelectionMode::Single)
        .margin_start(12)
        .margin_end(12)
        .build();
    let scrolled_window = ScrolledWindow::builder()
        .vexpand(true)
        .child(&list_box)
        .build();

    vbox.append(&toolbar);
    vbox.append(&action_status_label);
    vbox.append(&scrolled_window);

    refresh_file_list(
        &list_box,
        Rc::clone(&session),
        window.clone(),
        action_status_label.clone(),
    );

    let import_session = Rc::clone(&session);
    let import_window_weak = window.downgrade();
    let import_list_box = list_box.clone();
    let import_dialog_window = window.clone();
    let import_status = action_status_label.clone();

    import_btn.connect_clicked(move |_| {
        let chooser = FileChooserNative::new(
            Some("Select File to Encrypt & Import"),
            import_window_weak
                .upgrade()
                .as_ref()
                .map(|w| w.upcast_ref::<gtk::Window>()),
            FileChooserAction::Open,
            Some("_Import"),
            Some("_Cancel"),
        );

        let session_alloc = Rc::clone(&import_session);
        let list_box_alloc = import_list_box.clone();
        let dialog_window_alloc = import_dialog_window.clone();
        let status_alloc = import_status.clone();

        chooser.connect_response(move |dialog, response| {
            if response == ResponseType::Accept {
                if let Some(file) = dialog.file() {
                    if let Some(path) = file.path() {
                        let from_disk = path.to_string_lossy().to_string();
                        let vfs_name = path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();

                        let mut sess = session_alloc.borrow_mut();
                        let VaultSession {
                            ref mut file,
                            ref mut metadata,
                            ref unlocked_vault,
                            ref mut current_offset,
                        } = *sess;

                        if let Err(e) = crate::commands::import::handle_import(
                            from_disk,
                            vfs_name.clone(),
                            file,
                            metadata,
                            unlocked_vault,
                            current_offset,
                        ) {
                            status_alloc.set_label(&format!(
                                "<span foreground='red'>Import Error: {}</span>",
                                e
                            ));
                        } else {
                            let _ = file.sync_all();
                            drop(sess);

                            refresh_file_list(
                                &list_box_alloc,
                                Rc::clone(&session_alloc),
                                dialog_window_alloc.clone(),
                                status_alloc.clone(),
                            );
                            status_alloc.set_label(&format!(
                                "<span foreground='green'>Success: {} imported.</span>",
                                vfs_name
                            ));
                        }
                    }
                }
            }
            dialog.destroy();
        });
        chooser.show();
    });

    let export_session = Rc::clone(&session);
    let export_list_box = list_box.clone();
    let export_status = action_status_label.clone();
    let export_window_weak = window.downgrade();

    export_btn.connect_clicked(move |_| {
        let session_alloc = Rc::clone(&export_session);

        if let Some(row) = export_list_box.selected_row() {
            let index = row.index() as usize;
            let raw_vfs_name = { session_alloc.borrow().metadata.file_table[index].vfs_name.clone() };

            let safe_vfs_name = Path::new(&raw_vfs_name).file_name().unwrap_or_default().to_string_lossy().to_string();
            if safe_vfs_name.is_empty() { return; }

            let staging_dir = PathBuf::from("atom_staging");
            let _ = std::fs::create_dir_all(&staging_dir);
            let target_path_str = staging_dir.join(&safe_vfs_name).to_string_lossy().to_string();

            let mut sess = session_alloc.borrow_mut();
            let VaultSession { ref mut file, ref metadata, ref unlocked_vault, .. } = *sess;

            match crate::commands::export::handle_export(raw_vfs_name.clone(), target_path_str.clone(), metadata, file, unlocked_vault, false) {
                Ok(_) => export_status.set_label(&format!("<span foreground='green'>Success: Extracted to atom_staging/{}</span>", safe_vfs_name)),
                Err(e) => {
                    if e.to_string() == "ALREADY_EXISTS" {
                        let overwrite_dialog = Window::builder()
                            .transient_for(&export_window_weak.upgrade().unwrap())
                            .modal(true)
                            .title("File Already Exists")
                            .default_width(320)
                            .build();

                        let ov_vbox = GtkBox::builder().orientation(Orientation::Vertical).spacing(12).margin_top(16).margin_bottom(16).margin_start(16).margin_end(16).build();
                        ov_vbox.append(&Label::builder().label("This file already exists in the staging area.\nDo you want to force overwrite it?").wrap(true).build());
                        
                        let ov_btn_box = GtkBox::builder().orientation(Orientation::Horizontal).spacing(8).build();
                        let yes_btn = Button::builder().label("Yes, Overwrite").css_classes(["destructive-action"]).build();
                        let no_btn = Button::builder().label("Cancel").build();
                        
                        ov_btn_box.append(&yes_btn);
                        ov_btn_box.append(&no_btn);
                        ov_vbox.append(&ov_btn_box);
                        overwrite_dialog.set_child(Some(&ov_vbox));

                        let dialog_clone = overwrite_dialog.clone();
                        let status_clone = export_status.clone();
                        let session_clone = Rc::clone(&session_alloc);
                        let name_clone = raw_vfs_name.clone();
                        let path_clone = target_path_str.clone();

                        yes_btn.connect_clicked(move |_| {
                            let mut inner_sess = session_clone.borrow_mut();
                            let VaultSession { ref mut file, ref metadata, ref unlocked_vault, .. } = *inner_sess;
                            
                            match crate::commands::export::handle_export(name_clone.clone(), path_clone.clone(), metadata, file, unlocked_vault, true) {
                                Ok(_) => status_clone.set_label("<span foreground='green'>Success: File securely overwritten in staging.</span>"),
                                Err(err) => status_clone.set_label(&format!("<span foreground='red'>Overwrite failed: {}</span>", err)),
                            }
                            dialog_clone.close();
                        });

                        let dialog_clone_no = overwrite_dialog.clone();
                        no_btn.connect_clicked(move |_| { dialog_clone_no.close(); });

                        overwrite_dialog.present();
                        export_status.set_label("<span foreground='orange'>Waiting for overwrite confirmation...</span>");
                    } else {
                        export_status.set_label(&format!("<span foreground='red'>Export failed: {}</span>", e));
                    }
                }
            }
        } else {
            export_status.set_label("<span foreground='orange'>Warning: Please select a file from the list first.</span>");
        }
    });

    let window_p2p = window.clone();
    let current_vault_path_p2p = current_vault_path.clone();
    p2p_btn.connect_clicked(move |_| {
        show_p2p_dialog(&window_p2p, current_vault_path_p2p.clone());
    });

    let lock_window = window.clone();
    lock_btn.connect_clicked(move |_| {
        lock_window.close();
    });

    window.set_child(Some(&vbox));
}

fn show_p2p_dialog(parent: &ApplicationWindow, current_vault_path: String) {
    let dialog = Window::builder()
        .transient_for(parent)
        .modal(true)
        .title("P2P Network & Friends")
        .default_width(450)
        .destroy_with_parent(true)
        .build();

    let vbox = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(16)
        .margin_top(16)
        .margin_bottom(16)
        .margin_start(16)
        .margin_end(16)
        .build();

    // My Identity Section
    let my_id_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(4)
        .build();

    my_id_box.append(
        &Label::builder()
            .label("<b>Your Identity:</b>")
            .use_markup(true)
            .xalign(0.0)
            .build(),
    );

    let id_entry = Entry::builder().editable(false).can_focus(true).build();

    match crate::commands::id::get_id_string() {
        Ok(onion) => {
            let clean_onion = onion.trim_start_matches("atom://");
            id_entry.set_text(&format!("atom://{}", clean_onion));
        }
        Err(_) => id_entry.set_text("Identity not generated yet. Run daemon."),
    }

    my_id_box.append(&id_entry);
    vbox.append(&my_id_box);

    let add_friend_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(8)
        .build();
    add_friend_box.append(
        &Label::builder()
            .label("Add New Friend:")
            .xalign(0.0)
            .build(),
    );

    let friend_nick_entry = Entry::builder().placeholder_text("Friend Nickname").build();
    let friend_url_entry = Entry::builder().placeholder_text("atom://...").build();
    let add_friend_btn = Button::builder().label("Add to Address Book").build();
    let add_status = Label::builder().use_markup(true).build();

    add_friend_box.append(&friend_nick_entry);
    add_friend_box.append(&friend_url_entry);
    add_friend_box.append(&add_friend_btn);
    add_friend_box.append(&add_status);

    let add_status_clone = add_status.clone();
    add_friend_btn.connect_clicked(move |_| {
        let nick = friend_nick_entry.text().to_string();
        let url = friend_url_entry.text().to_string();

        if nick.is_empty() || url.is_empty() {
            add_status_clone
                .set_label("<span foreground='red'>Nickname and URL are required.</span>");
            return;
        }

        match crate::commands::friend::add_friend_core(&url, &nick) {
            Ok(msg) => {
                add_status_clone.set_label(&format!("<span foreground='green'>{}</span>", msg));
                friend_nick_entry.set_text("");
                friend_url_entry.set_text("");
            }
            Err(e) => {
                add_status_clone.set_label(&format!("<span foreground='red'>Error: {}</span>", e))
            }
        }
    });

    let sync_box = GtkBox::builder()
        .orientation(Orientation::Vertical)
        .spacing(8)
        .build();
    sync_box.append(
        &Label::builder()
            .label("Push Current Vault to Friend:")
            .xalign(0.0)
            .build(),
    );

    let friends = crate::commands::p2p_utils::load_friends();
    let friend_names: Vec<String> = friends.iter().map(|f| f.nickname.clone()).collect();

    let friend_dropdown = DropDown::from_strings(
        &friend_names
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<&str>>(),
    );

    let sync_btn = Button::builder()
        .label("Start Sync")
        .css_classes(["suggested-action"])
        .build();
    let sync_status = Label::builder().use_markup(true).wrap(true).build();

    sync_box.append(&friend_dropdown);
    sync_box.append(&sync_btn);
    sync_box.append(&sync_status);

    let sync_status_clone = sync_status.clone();
    let vault_path_clone = current_vault_path.clone();

    sync_btn.connect_clicked(move |_| {
        if friend_names.is_empty() {
            sync_status_clone.set_label("<span foreground='red'>No friends available.</span>");
            return;
        }

        let selected_index = friend_dropdown.selected();
        if selected_index as usize >= friend_names.len() {
            return;
        }

        let selected_friend = friend_names[selected_index as usize].clone();

        let status_msg = Arc::new(Mutex::new(String::from("Initiating background sync...")));
        let status_msg_thread = Arc::clone(&status_msg);
        let done_flag = Arc::new(AtomicBool::new(false));
        let done_flag_thread = Arc::clone(&done_flag);
        let sync_status_async = sync_status_clone.clone();

        gtk::glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
            if let Ok(msg) = status_msg.lock() {
                sync_status_async.set_label(&msg);
            }

            if done_flag.load(Ordering::SeqCst) {
                gtk::glib::ControlFlow::Break
            } else {
                gtk::glib::ControlFlow::Continue
            }
        });

        let vault_path_thread = vault_path_clone.clone();
        let friend_thread = selected_friend.clone();

        std::thread::spawn(move || {
            let (std_tx, std_rx) = std::sync::mpsc::channel();

            let status_msg_inner = Arc::clone(&status_msg_thread);
            std::thread::spawn(move || {
                while let Ok(msg) = std_rx.recv() {
                    if let Ok(mut lock) = status_msg_inner.lock() {
                        *lock = msg;
                    }
                }
            });

            if let Err(e) =
                crate::commands::sync::sync_core(&vault_path_thread, &friend_thread, Some(std_tx))
            {
                if let Ok(mut lock) = status_msg_thread.lock() {
                    *lock = format!("<span foreground='red'>Sync Failed: {}</span>", e);
                }
            } else {
                if let Ok(mut lock) = status_msg_thread.lock() {
                    *lock = format!(
                        "<span foreground='green'>Sync Complete with {}</span>",
                        friend_thread
                    );
                }
            }

            done_flag_thread.store(true, Ordering::SeqCst);
        });
    });

    vbox.append(&gtk::Separator::builder().build());
    vbox.append(&add_friend_box);
    vbox.append(&gtk::Separator::builder().build());
    vbox.append(&sync_box);

    dialog.set_child(Some(&vbox));
    dialog.present();
}

fn refresh_file_list(
    list_box: &ListBox,
    session: Rc<RefCell<VaultSession>>,
    window: ApplicationWindow,
    status_label: Label,
) {
    while let Some(child) = list_box.first_child() {
        list_box.remove(&child);
    }

    let metadata = &session.borrow().metadata;

    if metadata.file_table.is_empty() {
        let empty_label = Label::builder()
            .label("Vault is empty. Click 'Import File' to add.")
            .margin_top(20)
            .build();
        list_box.append(&empty_label);
        return;
    }

    for file_index in &metadata.file_table {
        let row_box = GtkBox::builder()
            .orientation(Orientation::Horizontal)
            .spacing(8)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(12)
            .margin_end(12)
            .build();

        let row_label = Label::builder()
            .label(&file_index.vfs_name)
            .xalign(0.0)
            .hexpand(true)
            .build();

        let open_btn = Button::builder()
            .label("Open")
            .css_classes(["flat"])
            .build();
        let delete_btn = Button::builder()
            .label("Delete")
            .css_classes(["destructive-action"])
            .build();

        let session_open = Rc::clone(&session);
        let status_open = status_label.clone();
        let vfs_name_open = file_index.vfs_name.clone();

        open_btn.connect_clicked(move |_| {
            status_open.set_label(&format!("Opening {} securely in Sandbox...", vfs_name_open));

            let mut sess = session_open.borrow_mut();
            let VaultSession {
                ref mut file,
                ref metadata,
                ref unlocked_vault,
                ..
            } = *sess;

            if let Some(target_file_index) = metadata
                .file_table
                .iter()
                .find(|f| f.vfs_name == vfs_name_open)
            {
                let done_flag = Arc::new(AtomicBool::new(false));
                let done_flag_thread = Arc::clone(&done_flag);

                if let Err(e) = crate::commands::view::execute(
                    file,
                    target_file_index,
                    unlocked_vault,
                    move || {
                        done_flag_thread.store(true, Ordering::SeqCst);
                    },
                ) {
                    status_open
                        .set_label(&format!("<span foreground='red'>Open failed: {}</span>", e));
                } else {
                    let status_open_async = status_open.clone();
                    let vfs_name_open_clone = vfs_name_open.clone();

                    gtk::glib::timeout_add_local(
                        std::time::Duration::from_millis(100),
                        move || {
                            if done_flag.load(Ordering::SeqCst) {
                                status_open_async.set_label(&format!(
                                    "<span foreground='green'>Closed securely: {}</span>",
                                    vfs_name_open_clone
                                ));
                                gtk::glib::ControlFlow::Break
                            } else {
                                gtk::glib::ControlFlow::Continue
                            }
                        },
                    );
                }
            } else {
                status_open.set_label("<span foreground='red'>Error: File index not found!</span>");
            }
        });

        let gesture = GestureClick::new();
        gesture.set_button(1);

        let session_rename = Rc::clone(&session);
        let window_clone = window.clone();
        let list_box_clone = list_box.clone();
        let status_rename = status_label.clone();
        let old_name = file_index.vfs_name.clone();

        gesture.connect_pressed(move |_, n_press, _, _| {
            if n_press == 2 {
                let dialog = Window::builder()
                    .transient_for(&window_clone)
                    .modal(true)
                    .title("Rename File")
                    .default_width(300)
                    .destroy_with_parent(true)
                    .build();

                let dialog_vbox = GtkBox::builder()
                    .orientation(Orientation::Vertical)
                    .spacing(12)
                    .margin_top(16)
                    .margin_bottom(16)
                    .margin_start(16)
                    .margin_end(16)
                    .build();
                let entry = Entry::builder().text(&old_name).build();
                let save_btn = Button::builder()
                    .label("Save New Name")
                    .css_classes(["suggested-action"])
                    .build();

                dialog_vbox.append(
                    &Label::builder()
                        .label("Enter new file name:")
                        .xalign(0.0)
                        .build(),
                );
                dialog_vbox.append(&entry);
                dialog_vbox.append(&save_btn);
                dialog.set_child(Some(&dialog_vbox));

                let dialog_clone = dialog.clone();
                let session_save = Rc::clone(&session_rename);
                let old_name_save = old_name.clone();
                let status_save = status_rename.clone();
                let list_box_save = list_box_clone.clone();
                let window_save = window_clone.clone();

                save_btn.connect_clicked(move |_| {
                    let new_name = entry.text().to_string();

                    if new_name.is_empty()
                        || new_name.contains('/')
                        || new_name.contains('\\')
                        || new_name.contains('\0')
                    {
                        status_save.set_label(
                            "<span foreground='red'>Rename Error: Invalid characters.</span>",
                        );
                        dialog_clone.close();
                        return;
                    }

                    let mut sess = session_save.borrow_mut();

                    if sess
                        .metadata
                        .file_table
                        .iter()
                        .any(|f| f.vfs_name == new_name)
                    {
                        status_save.set_label(
                            "<span foreground='red'>Rename Error: Name already exists.</span>",
                        );
                        dialog_clone.close();
                        return;
                    }

                    if let Some(file_idx) = sess
                        .metadata
                        .file_table
                        .iter_mut()
                        .find(|f| f.vfs_name == old_name_save)
                    {
                        file_idx.vfs_name = new_name.clone();
                    }

                    let _ = sess.file.sync_all();

                    status_save.set_label(&format!(
                        "<span foreground='green'>Renamed to: {}</span>",
                        new_name
                    ));
                    dialog_clone.close();

                    drop(sess);
                    refresh_file_list(
                        &list_box_save,
                        Rc::clone(&session_save),
                        window_save.clone(),
                        status_save.clone(),
                    );
                });

                dialog.present();
            }
        });

        let session_delete = Rc::clone(&session);
        let status_delete = status_label.clone();
        let list_box_delete = list_box.clone();
        let window_delete = window.clone();
        let vfs_name_delete = file_index.vfs_name.clone();

        delete_btn.connect_clicked(move |_| {
            let mut sess = session_delete.borrow_mut();
            let VaultSession {
                ref mut file,
                ref mut metadata,
                ref unlocked_vault,
                ref mut current_offset,
            } = *sess;

            match crate::commands::rm::handle_rm(
                vfs_name_delete.clone(),
                metadata,
                file,
                unlocked_vault,
                current_offset,
            ) {
                Ok(_) => {
                    status_delete.set_label(&format!(
                        "<span foreground='green'>Permanently Shredded: {}</span>",
                        vfs_name_delete
                    ));
                    drop(sess);
                    refresh_file_list(
                        &list_box_delete,
                        Rc::clone(&session_delete),
                        window_delete.clone(),
                        status_delete.clone(),
                    );
                }
                Err(e) => {
                    status_delete.set_label(&format!(
                        "<span foreground='red'>Delete failed: {}</span>",
                        e
                    ));
                }
            }
        });

        row_box.add_controller(gesture);
        row_box.append(&row_label);
        row_box.append(&open_btn);
        row_box.append(&delete_btn);

        list_box.append(&row_box);
    }
}