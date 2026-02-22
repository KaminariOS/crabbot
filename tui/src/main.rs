use clap::Parser;
use codex_arg0::arg0_dispatch_or_else;
use codex_tui::Cli;
use codex_tui::run_main;
use codex_utils_cli::CliConfigOverrides;

#[derive(Parser, Debug)]
struct TopCli {
    #[clap(flatten)]
    config_overrides: CliConfigOverrides,

    #[clap(flatten)]
    inner: Cli,
}

fn main() -> anyhow::Result<()> {
    arg0_dispatch_or_else(|codex_linux_sandbox_exe| async move {
        let top_cli = TopCli::parse();
        let mut inner = top_cli.inner;
        inner
            .config_overrides
            .raw_overrides
            .splice(0..0, top_cli.config_overrides.raw_overrides);
        let exit_info = run_main(inner, codex_linux_sandbox_exe).await?;
        let token_usage = exit_info.token_usage;
        let thread_id = exit_info.thread_id;
        let thread_name = exit_info.thread_name;
        if !token_usage.is_zero() {
            println!(
                "{}",
                codex_protocol::protocol::FinalOutput::from(token_usage),
            );
            if let Some(command) =
                codex_tui::util::resume_command(thread_name.as_deref(), thread_id)
            {
                let command = if supports_color::on(supports_color::Stream::Stdout).is_some() {
                    format!("\x1b[36m{command}\x1b[39m")
                } else {
                    command
                };
                println!("To continue this session, run {command}");
            }
        }
        Ok(())
    })
}
