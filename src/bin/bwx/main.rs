use crate::bin_error::ContextExt as _;
use clap::{CommandFactory as _, Parser as _};

mod actions;
mod bin_error;
mod commands;
mod sock;

#[derive(Debug, clap::Args)]
struct FindArgs {
    #[arg(help = "Name, URI or UUID of the entry to display", value_parser = commands::parse_needle)]
    needle: commands::Needle,
    #[arg(help = "Username of the entry to display")]
    user: Option<String>,
    #[arg(long, help = "Folder name to search in")]
    folder: Option<String>,
    #[arg(short, long, help = "Ignore case")]
    ignorecase: bool,
}

#[derive(Debug, clap::Parser)]
#[command(version, about = "Unofficial Bitwarden CLI")]
enum Opt {
    #[command(about = "Get or set configuration options")]
    Config {
        #[command(subcommand)]
        config: Config,
    },

    #[command(
        about = "Register this device with the Bitwarden server",
        long_about = "Register this device with the Bitwarden server\n\n\
            The official Bitwarden server includes bot detection to prevent \
            brute force attacks. In order to avoid being detected as bot \
            traffic, you will need to use this command to log in with your \
            personal API key (instead of your password) first before regular \
            logins will work."
    )]
    Register,

    #[command(about = "Log in to the Bitwarden server")]
    Login,

    #[command(about = "Unlock the local Bitwarden database")]
    Unlock,

    #[command(about = "Check if the local Bitwarden database is unlocked")]
    Unlocked,

    #[command(about = "Update the local copy of the Bitwarden database")]
    Sync,

    #[command(
        about = "List all entries in the local Bitwarden database",
        visible_alias = "ls"
    )]
    List {
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder, type. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(about = "Display the password for a given entry")]
    Get {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(short, long, help = "Field to get")]
        field: Option<String>,
        #[arg(long, help = "Display the notes in addition to the password")]
        full: bool,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
        #[cfg(feature = "clipboard")]
        #[structopt(short, long, help = "Copy result to clipboard")]
        clipboard: bool,
        #[structopt(short, long, help = "List fields in this entry")]
        list_fields: bool,
    },

    #[command(about = "Search for entries")]
    Search {
        #[arg(help = "Search term to locate entries")]
        term: String,
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
    },

    #[command(
        about = "Display the authenticator code for a given entry",
        visible_alias = "totp"
    )]
    Code {
        #[command(flatten)]
        find_args: FindArgs,
        #[cfg(feature = "clipboard")]
        #[structopt(long, help = "Copy result to clipboard")]
        clipboard: bool,
    },

    #[command(
        about = "Add a new password to the database",
        long_about = "Add a new password to the database\n\n\
            This command will open a text editor to enter \
            the password and notes. The editor to use is determined \
            by the value of the $VISUAL or $EDITOR environment variables.
            The first line will be saved as the password and the \
            remainder will be saved as a note."
    )]
    Add {
        #[arg(help = "Name of the password entry")]
        name: String,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
    },

    #[command(
        about = "Generate a new password",
        long_about = "Generate a new password\n\n\
            If given a password entry name, also save the generated \
            password to the database.",
        visible_alias = "gen",
        group = clap::ArgGroup::new("password-type").args(&[
            "no_symbols",
            "only_numbers",
            "nonconfusables",
            "diceware",
        ])
    )]
    Generate {
        #[arg(help = "Length of the password to generate")]
        len: usize,
        #[arg(help = "Name of the password entry")]
        name: Option<String>,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
        #[arg(
            long = "no-symbols",
            help = "Generate a password with no special characters"
        )]
        no_symbols: bool,
        #[arg(
            long = "only-numbers",
            help = "Generate a password consisting of only numbers"
        )]
        only_numbers: bool,
        #[arg(
            long,
            help = "Generate a password without visually similar \
                characters (useful for passwords intended to be \
                written down)"
        )]
        nonconfusables: bool,
        #[arg(
            long,
            help = "Generate a password of multiple dictionary \
                words chosen from the EFF word list. The len \
                parameter for this option will set the number \
                of words to generate, rather than characters."
        )]
        diceware: bool,
    },

    #[command(
        about = "Modify an existing password",
        long_about = "Modify an existing password\n\n\
            This command will open a text editor with the existing \
            password and notes of the given entry for editing. \
            The editor to use is determined  by the value of the \
            $VISUAL or $EDITOR environment variables. The first line \
            will be saved as the password and the remainder will be saved \
            as a note."
    )]
    Edit {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "Remove a given entry", visible_alias = "rm")]
    Remove {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "View the password history for a given entry")]
    History {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "Lock the password database")]
    Lock,

    #[command(about = "Remove the local copy of the password database")]
    Purge,

    #[command(name = "stop-agent", about = "Terminate the background agent")]
    StopAgent,

    #[command(
        name = "ssh-public-key",
        about = "Print the OpenSSH public key of an SSH key entry"
    )]
    SshPublicKey {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(
        name = "ssh-allowed-signers",
        about = "Print an allowed_signers file for every SSH key in the vault",
        long_about = "Print an allowed_signers file suitable for \
            `ssh-keygen -Y verify`. Each line is `<email> <public-key>`. \
            Pipe into a file and point git's \
            `gpg.ssh.allowedSignersFile` at it."
    )]
    SshAllowedSigners,

    #[command(
        name = "ssh-socket",
        about = "Print the filesystem path of bwx-agent's ssh-agent socket",
        long_about = "Print the filesystem path of bwx-agent's ssh-agent \
            socket, suitable for export to `SSH_AUTH_SOCK`. Honors \
            `BWX_PROFILE` and `XDG_RUNTIME_DIR`."
    )]
    SshSocket,

    #[command(
        name = "touchid",
        about = "Manage macOS Touch ID enrollment (macOS only)"
    )]
    TouchId {
        #[command(subcommand)]
        cmd: TouchIdCmd,
    },

    #[command(
        name = "setup-macos",
        about = "Install the bwx-agent LaunchAgent + set SSH_AUTH_SOCK \
            for GUI apps (macOS only)",
        long_about = "One-shot macOS environment setup. Writes a \
            LaunchAgent plist that exports `SSH_AUTH_SOCK` to the \
            current login session at every login, so Finder/Spotlight-\
            launched GUI apps (IDEs, git clients) see bwx-agent's ssh \
            socket. Also runs `launchctl setenv` for the current \
            session so existing GUI apps can be Cmd-Q'd and relaunched \
            without a logout."
    )]
    SetupMacos {
        #[arg(long, help = "Overwrite any existing LaunchAgent file")]
        force: bool,
    },

    #[command(
        name = "teardown-macos",
        about = "Uninstall what `bwx setup-macos` created (macOS only)"
    )]
    TeardownMacos,

    #[command(
        name = "gen-completions",
        about = "Generate completion script for the given shell"
    )]
    GenCompletions { shell: CompletionShell },
}

impl Opt {
    /// Human-readable context surfaced in Touch ID / pinentry prompts on
    /// the agent side. Where a single argument uniquely identifies the
    /// target (the needle for `get`/`code`/`edit`/etc.) we include it.
    fn purpose(&self) -> String {
        match self {
            Self::Get { find_args, .. }
            | Self::Code { find_args, .. }
            | Self::Edit { find_args }
            | Self::Remove { find_args }
            | Self::History { find_args }
            | Self::SshPublicKey { find_args } => {
                format!("bwx {} {}", self.subcommand_name(), find_args.needle)
            }
            Self::Search { term, .. } => format!("bwx search {term}"),
            Self::Add { name, .. }
            | Self::Generate {
                name: Some(name), ..
            } => {
                format!("bwx {} {name}", self.subcommand_name())
            }
            _ => format!("bwx {}", self.subcommand_name()),
        }
    }

    fn subcommand_name(&self) -> String {
        match self {
            Self::Config { config } => {
                format!("config {}", config.subcommand_name())
            }
            Self::Register => "register".to_string(),
            Self::Login => "login".to_string(),
            Self::Unlock => "unlock".to_string(),
            Self::Unlocked => "unlocked".to_string(),
            Self::Sync => "sync".to_string(),
            Self::List { .. } => "list".to_string(),
            Self::Get { .. } => "get".to_string(),
            Self::Search { .. } => "search".to_string(),
            Self::Code { .. } => "code".to_string(),
            Self::Add { .. } => "add".to_string(),
            Self::Generate { .. } => "generate".to_string(),
            Self::Edit { .. } => "edit".to_string(),
            Self::Remove { .. } => "remove".to_string(),
            Self::History { .. } => "history".to_string(),
            Self::Lock => "lock".to_string(),
            Self::Purge => "purge".to_string(),
            Self::StopAgent => "stop-agent".to_string(),
            Self::SshPublicKey { .. } => "ssh-public-key".to_string(),
            Self::SshAllowedSigners => "ssh-allowed-signers".to_string(),
            Self::SshSocket => "ssh-socket".to_string(),
            Self::TouchId { cmd } => {
                format!("touchid {}", cmd.subcommand_name())
            }
            Self::SetupMacos { .. } => "setup-macos".to_string(),
            Self::TeardownMacos => "teardown-macos".to_string(),
            Self::GenCompletions { .. } => "gen-completions".to_string(),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
}

#[derive(Debug, clap::Parser)]
enum TouchIdCmd {
    #[command(
        about = "Enroll the current vault under a Touch ID-gated Keychain \
            wrapper key"
    )]
    Enroll,
    #[command(
        about = "Remove the Touch ID enrollment (Keychain item + blob)"
    )]
    Disable,
    #[command(about = "Show the current Touch ID enrollment status")]
    Status,
}

impl TouchIdCmd {
    fn subcommand_name(&self) -> &'static str {
        match self {
            Self::Enroll => "enroll",
            Self::Disable => "disable",
            Self::Status => "status",
        }
    }
}

#[derive(Debug, clap::Parser)]
enum Config {
    #[command(
        about = "Show configuration settings",
        long_about = "Without arguments, print all configuration \
            settings as JSON. With a key argument, print just that \
            key's current value in plain text."
    )]
    Show {
        #[arg(help = "Configuration key to read (omit to dump all)")]
        key: Option<String>,
    },
    #[command(about = "Set a configuration option")]
    Set {
        #[arg(help = "Configuration key to set")]
        key: String,
        #[arg(help = "Value to set the configuration option to")]
        value: String,
    },
    #[command(about = "Reset a configuration option to its default")]
    Unset {
        #[arg(help = "Configuration key to unset")]
        key: String,
    },
}

impl Config {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Show { .. } => "show",
            Self::Set { .. } => "set",
            Self::Unset { .. } => "unset",
        }
        .to_string()
    }
}

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
