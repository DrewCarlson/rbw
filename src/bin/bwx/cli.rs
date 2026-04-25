use crate::commands;

#[derive(Debug, clap::Args)]
pub struct FindArgs {
    #[arg(help = "Name, URI or UUID of the entry to display", value_parser = commands::parse_needle)]
    pub needle: commands::Needle,
    #[arg(help = "Username of the entry to display")]
    pub user: Option<String>,
    #[arg(long, help = "Folder name to search in")]
    pub folder: Option<String>,
    #[arg(short, long, help = "Ignore case")]
    pub ignorecase: bool,
}

#[derive(Debug, clap::Parser)]
#[command(version, about = "Unofficial Bitwarden CLI")]
pub enum Opt {
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

    #[command(
        about = "Run a command with vault fields injected as env vars",
        long_about = "Run a command with vault fields injected as \
            environment variables.\n\n\
            Each `--env VAR=ENTRY[#FIELD]` resolves a vault entry's \
            field (defaulting to `password`) and binds it to `VAR` for \
            the child process. The value is passed via execve() only — \
            it is never written to disk, and the parent zeroizes its \
            in-process copy as soon as the child is spawned. Useful as \
            a drop-in replacement for `direnv` + plaintext `.env` \
            files.\n\n\
            Examples:\n  \
                bwx exec --env DB_URL=db/prod#uri -- terraform apply\n  \
                bwx exec --env GH=github.com -- gh pr list"
    )]
    Exec {
        #[arg(
            long = "env",
            value_name = "VAR=ENTRY[#FIELD]",
            help = "Bind a vault field to an environment variable; \
                may be given multiple times",
            action = clap::ArgAction::Append,
            required = true,
        )]
        env: Vec<String>,
        #[arg(long, help = "Folder to scope entry lookups to")]
        folder: Option<String>,
        #[arg(short, long, help = "Ignore case when matching entry names")]
        ignorecase: bool,
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            num_args = 1..,
            value_name = "CMD",
            help = "Command and arguments to execute (place after `--`)"
        )]
        command: Vec<String>,
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
    /// the agent side. Includes the needle when one argument uniquely
    /// identifies the target.
    pub fn purpose(&self) -> String {
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

    pub fn subcommand_name(&self) -> String {
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
            Self::Exec { .. } => "exec".to_string(),
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
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
}

#[derive(Debug, clap::Parser)]
pub enum TouchIdCmd {
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
pub enum Config {
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
