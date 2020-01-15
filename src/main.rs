/*
 * This file is part of Master Password.
 *
 * Master Password is free software: you can redistribute it and/or modify
 * Mit under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Master Password is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Master Password. If not, see <http://www.gnu.org/licenses/>.
 */

mod arg_parse;
mod identicon;
mod core;
mod common;
mod benchmark;

use std::io::{self, Write};
use rpassword::read_password;

#[cfg(any(linux, unix))]
use wl_clipboard_rs::copy::{ClipboardType, MimeType, Options, ServeRequests, Source};
#[cfg(any(linux, unix))]
use nix::unistd::{fork, ForkResult};

fn main() {
    let mpw_options = arg_parse::get_opts();

    print!("Your master password: ");
    let _ = io::stdout().flush();
    let password = read_password().unwrap();

    let identity = identicon::generate(&mpw_options.user, &password);
    let master_key = match core::master_key_for_user(&mpw_options.user,
                                                     &password,
                                                     &mpw_options.algo,
                                                     &mpw_options.variant) {
        Some(val) => val,
        None => panic!("Master Key Error"),
    };

    let password = match core::password_for_site(&master_key,
                                                 &mpw_options.site,
                                                 &mpw_options.template,
                                                 &mpw_options.counter,
                                                 &mpw_options.variant,
                                                 &mpw_options.context,
                                                 &mpw_options.algo) {
        Some(val) => val,
        None => panic!("Password Error"),
    };

    if !mpw_options.clip {
        return println!("[ {} ]: {}", identity, password)
    }

    copy_to_clipboard(password, identity);
}

#[cfg(target_os = "linux")]
fn copy_to_clipboard(password: String, identity: String) {
    let mut options = Options::new();
    options
        .serve_requests(ServeRequests::Unlimited)
        .foreground(true)
        .clipboard(ClipboardType::Both)
        .trim_newline(true);

    let source = Source::Bytes(Box::from(password.as_bytes()));

    if let Ok(prepared_copy) = options.prepare_copy(source, MimeType::Text) {
        if let ForkResult::Child = fork().unwrap() {
            println!("[ {} ]: copied to clipboard", identity);
            drop(prepared_copy.serve());
        }
    } else {
        eprintln!("[ {} ]: could not prepare copy", identity);
    }
}
