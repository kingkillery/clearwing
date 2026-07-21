"""OSS-Fuzz CLI — clearwing ossfuzz.

Subcommands:
    scaffold     Generate an OSS-Fuzz project triple for a repo
    list         List projects from a local google/oss-fuzz checkout
    build        Build fuzz targets (base-builder + build.sh contract)
    fuzz         Run a built fuzzer, collect + dedup crashes, emit findings
    check-patch  Buttercup-style patch validation against a crash input
    run          build + fuzz + findings JSON in one shot
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import asdict


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "ossfuzz",
        help="OSS-Fuzz project format builds, fuzzing, and patch validation",
    )
    sub = parser.add_subparsers(dest="ossfuzz_action")

    scaffold = sub.add_parser(
        "scaffold",
        help="Generate project.yaml + Dockerfile + build.sh for a repo",
    )
    scaffold.add_argument("name", help="OSS-Fuzz project name ([a-z0-9][a-z0-9_-]*)")
    scaffold.add_argument("--language", default="c", help="Project language (default: c)")
    scaffold.add_argument("--repo", default="", help="Upstream git URL (omit for local trees)")
    scaffold.add_argument("--homepage", default="")
    scaffold.add_argument(
        "--sanitizers",
        default="address,undefined",
        help="Comma list (default: address,undefined)",
    )
    scaffold.add_argument(
        "--harnesses",
        nargs="*",
        default=None,
        help="Harness source paths relative to the repo root",
    )
    scaffold.add_argument("--out", required=True, help="Output directory for the triple")

    list_cmd = sub.add_parser(
        "list",
        help="List projects from a local google/oss-fuzz checkout",
    )
    list_cmd.add_argument(
        "--oss-fuzz-dir",
        default=None,
        help="Checkout root (default: $CLEARWING_OSS_FUZZ_DIR or ~/.clearwing/oss-fuzz)",
    )
    list_cmd.add_argument("--language", default=None)
    list_cmd.add_argument("--sanitizer", default=None)
    list_cmd.add_argument("--json", action="store_true", help="Emit JSON instead of a table")

    build = sub.add_parser("build", help="Build fuzz targets for a project triple")
    build.add_argument("project_dir", help="Dir containing project.yaml + build.sh")
    build.add_argument("--source", required=True, help="Host checkout of the target source")
    build.add_argument("--out", required=True, help="$OUT dir for fuzzer binaries")
    build.add_argument("--sanitizer", default="address")
    build.add_argument("--image", default=None, help="Override base-builder image")
    build.add_argument("--apt", nargs="*", default=None, help="Extra apt packages")

    fuzz = sub.add_parser("fuzz", help="Run a built fuzzer and collect crashes")
    fuzz.add_argument("out_dir", help="$OUT dir containing the fuzzer binary")
    fuzz.add_argument("--fuzzer", required=True, help="Fuzzer binary name inside $OUT")
    fuzz.add_argument("--seconds", type=int, default=60, help="max_total_time (default: 60)")
    fuzz.add_argument("--corpus", default=None, help="Seed corpus dir")
    fuzz.add_argument("--crashes-dir", default=None, help="Crash artifact output dir")
    fuzz.add_argument("--image", default=None, help="Override runner image")
    fuzz.add_argument("--project", default="", help="Project name (improves finding file paths)")
    fuzz.add_argument("--findings-json", default=None, help="Write findings JSON here")

    check = sub.add_parser(
        "check-patch",
        help="Validate a patch: reproduce crash, patch, rebuild, confirm gone",
    )
    check.add_argument("project_dir", help="Dir containing project.yaml + build.sh")
    check.add_argument("--source", required=True)
    check.add_argument("--diff", required=True, help="Unified diff file to validate")
    check.add_argument("--crash", required=True, help="Crash input file to replay")
    check.add_argument("--fuzzer", default=None, help="Fuzzer name (needed if >1)")
    check.add_argument("--sanitizer", default="address")
    check.add_argument("--image", default=None)

    run = sub.add_parser("run", help="build + fuzz + findings JSON in one shot")
    run.add_argument("project_dir", help="Dir containing project.yaml + build.sh")
    run.add_argument("--source", required=True)
    run.add_argument("--fuzzer", default=None, help="Fuzzer to run (default: all built)")
    run.add_argument("--seconds", type=int, default=60)
    run.add_argument("--sanitizer", default="address")
    run.add_argument("--work-dir", default=None, help="Build/fuzz output base dir")
    run.add_argument("--findings-json", default=None)

    return parser


def handle(cli, args):
    action = getattr(args, "ossfuzz_action", None)
    if not action:
        cli.console.print(
            "[yellow]Usage: clearwing ossfuzz <scaffold|list|build|fuzz|check-patch|run>[/yellow]",
        )
        return

    handlers = {
        "scaffold": _handle_scaffold,
        "list": _handle_list,
        "build": _handle_build,
        "fuzz": _handle_fuzz,
        "check-patch": _handle_check_patch,
        "run": _handle_run,
    }
    handler = handlers.get(action)
    if handler:
        handler(cli, args)
    else:
        cli.console.print(f"[red]Unknown action: {action}[/red]")


# --- scaffold -----------------------------------------------------------------


def _handle_scaffold(cli, args):
    from ...ossfuzz.project import scaffold_project

    try:
        project_dir = scaffold_project(
            name=args.name,
            language=args.language,
            out_dir=args.out,
            main_repo=args.repo,
            homepage=args.homepage,
            sanitizers=[s.strip() for s in args.sanitizers.split(",") if s.strip()],
            harnesses=args.harnesses,
        )
    except ValueError as exc:
        cli.console.print(f"[red]{exc}[/red]")
        sys.exit(1)
    cli.console.print(f"[green]Scaffolded OSS-Fuzz project:[/green] {project_dir}")
    cli.console.print("  project.yaml, Dockerfile, build.sh")
    cli.console.print(
        "[dim]Next: complete the project-build section of build.sh, then "
        f"`clearwing ossfuzz build {project_dir} --source <checkout> --out <out>`[/dim]",
    )


# --- list ---------------------------------------------------------------------


def _handle_list(cli, args):
    from ...ossfuzz.project import load_oss_fuzz_corpus, resolve_oss_fuzz_dir

    root = resolve_oss_fuzz_dir(args.oss_fuzz_dir)
    if root is None:
        cli.console.print(
            "[red]No google/oss-fuzz checkout found.[/red] Clone it:\n"
            "  git clone --depth 1 https://github.com/google/oss-fuzz "
            "~/.clearwing/oss-fuzz\n"
            "or set CLEARWING_OSS_FUZZ_DIR.",
        )
        sys.exit(1)

    corpus = load_oss_fuzz_corpus(
        root,
        language=args.language,
        sanitizer=args.sanitizer,
    )
    if args.json:
        cli.console.print(
            json.dumps(
                [
                    {
                        "name": c.name,
                        "language": c.project.language,
                        "sanitizers": c.project.sanitizers,
                        "main_repo": c.project.main_repo,
                    }
                    for c in corpus
                ],
                indent=2,
            )
        )
        return

    cli.console.print(f"[bold]{len(corpus)} projects[/bold] in {root}")
    for c in corpus:
        cli.console.print(
            f"  {c.name:<40} {c.project.language:<12} {','.join(c.project.sanitizers)}",
        )


# --- build ---------------------------------------------------------------------


def _handle_build(cli, args):
    _setup_logging()
    build_result = _do_build(
        args.project_dir,
        args.source,
        args.out,
        sanitizer=args.sanitizer,
        image=args.image,
        apt=args.apt,
    )
    console = cli.console
    if not build_result.success:
        console.print(f"[red]Build failed:[/red] {build_result.error}")
        if build_result.log:
            console.print(f"[dim]{build_result.log[-1500:]}[/dim]")
        sys.exit(1)
    console.print(
        f"[green]Build OK[/green] ({build_result.duration_seconds:.0f}s, {build_result.image})",
    )
    for binary in build_result.fuzzer_binaries:
        console.print(f"  fuzzer: {binary}")


def _do_build(project_dir, source, out, *, sanitizer, image, apt=None, patch_diff=None):
    from ...ossfuzz.builder import BuildConfig, OssFuzzBuilder
    from ...ossfuzz.project import load_project_yaml

    project = load_project_yaml(project_dir)
    config = BuildConfig(
        sanitizer=sanitizer,
        image=image,
        apt_packages=apt or [],
    )
    return OssFuzzBuilder(config).build(
        project,
        project_dir,
        source,
        out,
        patch_diff=patch_diff,
    )


# --- fuzz ---------------------------------------------------------------------


def _handle_fuzz(cli, args):
    _setup_logging()
    result = _do_fuzz(
        args.out_dir,
        args.fuzzer,
        seconds=args.seconds,
        corpus=args.corpus,
        crashes_dir=args.crashes_dir,
        image=args.image,
    )
    _report_fuzz(cli, result, args.project, args.findings_json)


def _do_fuzz(out_dir, fuzzer, *, seconds, corpus=None, crashes_dir=None, image=None):
    from ...ossfuzz.runner import FuzzConfig, FuzzRunner

    config = FuzzConfig(
        image=image,
        corpus_dir=corpus,
        crashes_dir=crashes_dir or "",
        max_total_time_seconds=seconds,
    )
    return FuzzRunner(config).fuzz(out_dir, fuzzer)


def _report_fuzz(cli, result, project_name, findings_json):
    console = cli.console
    if not result.success:
        console.print(f"[red]Fuzz run failed:[/red] {result.error}")
        sys.exit(1)
    console.print(
        f"[green]Fuzz run complete[/green] ({result.duration_seconds:.0f}s, "
        f"{result.runs_executed} execs): "
        f"{len(result.crashes)} crashes, {result.unique_crash_count} unique",
    )
    for crash in result.crashes:
        marker = "new" if crash.is_new else "dup"
        console.print(
            f"  [{marker}] {crash.report.crash_type or 'unknown'} "
            f"sig={crash.signature} {crash.input_path or crash.artifact_name}",
        )

    if findings_json:
        from ...ossfuzz.bridge import fuzz_run_to_findings

        findings = fuzz_run_to_findings(result, project_name=project_name)
        payload = [asdict(f) for f in findings]
        with open(findings_json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        console.print(f"[green]Wrote {len(findings)} findings[/green] → {findings_json}")


# --- check-patch -----------------------------------------------------------------


def _handle_check_patch(cli, args):
    _setup_logging()
    from ...ossfuzz.builder import BuildConfig
    from ...ossfuzz.patchcheck import validate_patch
    from ...ossfuzz.project import load_project_yaml

    try:
        patch_diff = open(args.diff, encoding="utf-8").read()
    except OSError as exc:
        cli.console.print(f"[red]Cannot read diff: {exc}[/red]")
        sys.exit(1)

    project = load_project_yaml(args.project_dir)
    result = validate_patch(
        project,
        args.project_dir,
        args.source,
        patch_diff,
        args.crash,
        fuzzer_name=args.fuzzer,
        build_config=BuildConfig(sanitizer=args.sanitizer, image=args.image),
    )

    console = cli.console
    console.print(f"  reproduced on vulnerable build: {result.reproduced_on_vulnerable}")
    console.print(f"  patch applied + rebuilt:        {result.rebuilt}")
    if result.validated:
        console.print("[green]PATCH VALIDATED[/green] — crash gone after patch")
    else:
        console.print(f"[red]NOT VALIDATED[/red] — {result.notes}")
        if result.new_crash_after_patch:
            console.print(
                "[yellow]warning: input triggers a DIFFERENT crash after "
                "patching (sig "
                f"{result.post_patch_signature})[/yellow]",
            )
    if not result.validated:
        sys.exit(1)


# --- run --------------------------------------------------------------------------


def _handle_run(cli, args):
    _setup_logging()
    import tempfile
    from pathlib import Path

    work = (
        Path(args.work_dir)
        if args.work_dir
        else Path(tempfile.mkdtemp(prefix="clearwing-ossfuzz-"))
    )
    out_dir = work / "out"

    cli.console.print(f"[dim]work dir: {work}[/dim]")
    build_result = _do_build(
        args.project_dir,
        args.source,
        out_dir,
        sanitizer=args.sanitizer,
        image=None,
    )
    if not build_result.success:
        cli.console.print(f"[red]Build failed:[/red] {build_result.error}")
        cli.console.print(f"[dim]{build_result.log[-1500:]}[/dim]")
        sys.exit(1)
    cli.console.print(
        f"[green]Build OK[/green]: {', '.join(build_result.fuzzer_binaries) or '(no fuzzers)'}",
    )

    fuzzers = [args.fuzzer] if args.fuzzer else build_result.fuzzer_binaries
    if not fuzzers:
        cli.console.print("[yellow]No fuzzer binaries to run.[/yellow]")
        return

    from ...ossfuzz.project import load_project_yaml

    project = load_project_yaml(args.project_dir)
    all_findings = []
    from ...ossfuzz.bridge import fuzz_run_to_findings

    for fuzzer in fuzzers:
        cli.console.print(f"[bold]Fuzzing {fuzzer}[/bold] ({args.seconds}s)…")
        result = _do_fuzz(
            out_dir,
            fuzzer,
            seconds=args.seconds,
            crashes_dir=str(work / "crashes"),
        )
        _report_fuzz(cli, result, project.name, None)
        all_findings.extend(fuzz_run_to_findings(result, project_name=project.name))

    findings_path = args.findings_json or str(work / "findings.json")
    with open(findings_path, "w", encoding="utf-8") as fh:
        json.dump([asdict(f) for f in all_findings], fh, indent=2)
    cli.console.print(
        f"[green]{len(all_findings)} unique findings[/green] → {findings_path}",
    )


def _setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
        force=True,
    )
