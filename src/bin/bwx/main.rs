use clap::{CommandFactory as _, Parser as _};

use crate::bin_error::ContextExt as _;
use crate::cli::{CompletionShell, Config, Opt, TouchIdCmd};

mod actions;
mod bin_error;
mod cli;
mod commands;
mod sock;

fn main() {
    let opt = Opt::parse();

    bwx::logger::init("info");

    let subcommand_name = opt.subcommand_name();
    actions::set_purpose(opt.purpose());
    let res = match opt {
        Opt::Config { config } => match config {
            Config::Show { key } => commands::config_show(key.as_deref()),
            Config::Set { key, value } => commands::config_set(&key, &value),
            Config::Unset { key } => commands::config_unset(&key),
        },
        Opt::Register => commands::register(),
        Opt::Login => commands::login(),
        Opt::Unlock => commands::unlock(),
        Opt::Unlocked => commands::unlocked(),
        Opt::Sync => commands::sync(),
        Opt::List { fields, raw } => commands::list(&fields, raw),
        Opt::Get {
            find_args,
            field,
            full,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            list_fields,
        } => commands::get(
            find_args.needle.clone(),
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            field.as_deref(),
            full,
            raw,
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
            list_fields,
        ),
        Opt::Search {
            term,
            fields,
            folder,
            raw,
        } => commands::search(&term, &fields, folder.as_deref(), raw),
        Opt::Code {
            find_args,
            #[cfg(feature = "clipboard")]
            clipboard,
        } => commands::code(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
        ),
        Opt::Add {
            name,
            user,
            uri,
            folder,
        } => commands::add(
            &name,
            user.as_deref(),
            &uri.iter()
                // XXX not sure what the ui for specifying the match type
                // should be
                .map(|uri| (uri.clone(), None))
                .collect::<Vec<_>>(),
            folder.as_deref(),
        ),
        Opt::Generate {
            len,
            name,
            user,
            uri,
            folder,
            no_symbols,
            only_numbers,
            nonconfusables,
            diceware,
        } => {
            let ty = if no_symbols {
                bwx::pwgen::Type::NoSymbols
            } else if only_numbers {
                bwx::pwgen::Type::Numbers
            } else if nonconfusables {
                bwx::pwgen::Type::NonConfusables
            } else if diceware {
                bwx::pwgen::Type::Diceware
            } else {
                bwx::pwgen::Type::AllChars
            };
            commands::generate(
                name.as_deref(),
                user.as_deref(),
                &uri.iter()
                    // XXX not sure what the ui for specifying the match type
                    // should be
                    .map(|uri| (uri.clone(), None))
                    .collect::<Vec<_>>(),
                folder.as_deref(),
                len,
                ty,
            )
        }
        Opt::Edit { find_args } => commands::edit(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::Remove { find_args } => commands::remove(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::History { find_args } => commands::history(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::Exec {
            env,
            folder,
            ignorecase,
            command,
        } => commands::exec(&env, folder.as_deref(), ignorecase, &command),
        Opt::Lock => commands::lock(),
        Opt::Purge => commands::purge(),
        Opt::StopAgent => commands::stop_agent(),
        Opt::SshPublicKey { find_args } => commands::ssh_public_key(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::SshAllowedSigners => commands::ssh_allowed_signers(),
        Opt::SshSocket => {
            commands::ssh_socket();
            Ok(())
        }
        Opt::TouchId { cmd } => match cmd {
            TouchIdCmd::Enroll => commands::touchid_enroll(),
            TouchIdCmd::Disable => commands::touchid_disable(),
            TouchIdCmd::Status => commands::touchid_status(),
        },
        Opt::SetupMacos { force } => commands::setup_macos(force),
        Opt::TeardownMacos => commands::teardown_macos(),
        Opt::GenCompletions { shell } => {
            match shell {
                CompletionShell::Bash => {
                    clap_complete::generate(
                        clap_complete::Shell::Bash,
                        &mut Opt::command(),
                        "bwx",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/bwx.bash"));
                }
                CompletionShell::Fish => {
                    clap_complete::generate(
                        clap_complete::Shell::Fish,
                        &mut Opt::command(),
                        "bwx",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/bwx.fish"));
                }
                CompletionShell::Zsh => {
                    clap_complete::generate(
                        clap_complete::Shell::Zsh,
                        &mut Opt::command(),
                        "bwx",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/bwx.zsh"));
                }
                CompletionShell::Powershell => {
                    clap_complete::generate(
                        clap_complete::Shell::PowerShell,
                        &mut Opt::command(),
                        "bwx",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Elvish => {
                    clap_complete::generate(
                        clap_complete::Shell::Elvish,
                        &mut Opt::command(),
                        "bwx",
                        &mut std::io::stdout(),
                    );
                }
            }
            Ok(())
        }
    }
    .with_context(|| format!("bwx {subcommand_name}"));

    if let Err(e) = res {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
