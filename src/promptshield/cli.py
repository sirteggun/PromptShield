"""Command-line interface for PromptShield.

Supports interactive multi-line input, piping from stdin, file input,
JSON reports for CI/CD, risk breakdown, sanitization, policy decisions,
and meaningful exit codes.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from colorama import Fore, Style, init as colorama_init

from promptshield._version import __version__
from promptshield.breakdown import RiskBreakdown
from promptshield.classifier import PromptLabel
from promptshield.container import build_service
from promptshield.explainer import RiskExplanation
from promptshield.finding import Finding, Severity
from promptshield.pipeline import AnalysisResult
from promptshield.policy_engine import PolicyAction, PolicyDecision
from promptshield.sanitizer import SanitizationResult, label_for_token
from promptshield.scoring import RiskBand
from promptshield.service import (
    PromptShieldService,
    compute_final_exit_code,
    compute_risk_exit_code,
)

logger = logging.getLogger(__name__)

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.INFO: Fore.CYAN,
    Severity.LOW: Fore.GREEN,
    Severity.MEDIUM: Fore.YELLOW,
    Severity.HIGH: Fore.RED,
    Severity.CRITICAL: Fore.MAGENTA,
}

_BAND_COLORS: dict[RiskBand, str] = {
    RiskBand.GREEN: Fore.GREEN,
    RiskBand.YELLOW: Fore.YELLOW,
    RiskBand.RED: Fore.RED,
}

_BAND_LABELS: dict[RiskBand, str] = {
    RiskBand.GREEN: "VERDE (basso rischio)",
    RiskBand.YELLOW: "GIALLO (rischio medio)",
    RiskBand.RED: "ROSSO (alto rischio)",
}

_BAND_JSON: dict[RiskBand, str] = {
    RiskBand.GREEN: "GREEN",
    RiskBand.YELLOW: "YELLOW",
    RiskBand.RED: "RED",
}

_ACTION_COLORS: dict[PolicyAction, str] = {
    PolicyAction.BLOCK: Fore.RED,
    PolicyAction.WARN: Fore.YELLOW,
    PolicyAction.ALLOW: Fore.GREEN,
}


def get_package_version() -> str:
    """Return package version (same source as ``promptshield.__version__``)."""
    return __version__


def compute_exit_code(result: AnalysisResult) -> int:
    """Map analysis result to a CI-friendly process exit code (risk only)."""
    return compute_risk_exit_code(result)


# Re-export for tests / external callers
__all_exit__ = ("compute_exit_code", "compute_final_exit_code")


def build_json_report(
    result: AnalysisResult,
    *,
    breakdown: RiskBreakdown,
    decision: PolicyDecision,
    sanitization: SanitizationResult | None = None,
    include_sanitize_flag: bool = False,
    intelligence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the top-level JSON document (delegates to service report shape)."""
    from promptshield.service import ServiceAnalysisResult

    svc_result = ServiceAnalysisResult(
        analysis=result,
        decision=decision,
        breakdown=breakdown,
        exit_code=compute_final_exit_code(result, decision),
        sanitization=sanitization,
        options={"sanitize": include_sanitize_flag},
    )
    if intelligence is not None and "classification" in intelligence:
        from promptshield.classifier import PromptLabel as PL
        from promptshield.explainer import RiskExplanation as RE

        # Attach pre-built intelligence via explanation presence
        exp_data = intelligence.get("explanation", {})
        svc_result.explanation = RE(
            summary=str(exp_data.get("summary", "")),
            risk_factors=list(exp_data.get("risk_factors", [])),
            safe_after_sanitization=bool(
                exp_data.get("safe_after_sanitization", False)
            ),
            recommended_action=str(exp_data.get("recommended_action", "ALLOW")),
        )
        svc_result.labels = [
            PL(
                label=str(item.get("label", "unknown")),
                confidence=float(item.get("confidence", 0)),
                evidence=list(item.get("evidence", [])),
            )
            for item in intelligence.get("classification", [])
        ]
    report = svc_result.to_report_dict()
    if intelligence is not None and "intelligence" not in report.get("analysis", {}):
        report["analysis"]["intelligence"] = intelligence
    return report


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _read_prompt_from_stdin() -> str:
    if not sys.stdin.isatty():
        return sys.stdin.read()

    print(
        "Inserisci il prompt (termina con CTRL+D / CTRL+Z oppure una riga con solo '.'):",
        file=sys.stderr,
    )
    lines: list[str] = []
    try:
        while True:
            line = input()
            if line.strip() == ".":
                break
            lines.append(line)
    except EOFError:
        pass
    return "\n".join(lines)


def _read_prompt(file_path: Path | None) -> str:
    if file_path is not None:
        return file_path.read_text(encoding="utf-8")
    return _read_prompt_from_stdin()


def _print_finding(finding: Finding, index: int) -> None:
    color = _SEVERITY_COLORS.get(finding.severity, Fore.WHITE)
    category = finding.category or "—"
    print(
        f"  {color}[{index}] {finding.detector_name} "
        f"({finding.severity.value} / {category}){Style.RESET_ALL}"
    )
    # Never print full secret/PII — only preview or replacement token.
    match_display = finding.matched_text_preview()
    if finding.replacement_token:
        match_display = (
            f"{match_display} -> {finding.replacement_token}"
            if match_display
            else finding.replacement_token
        )
    print(f"      match      : {match_display!r}")
    print(f"      span       : [{finding.start_position}, {finding.end_position})")
    print(f"      weight     : {finding.weight}")
    if finding.replacement_token:
        print(f"      replace    : {finding.replacement_token}")
    print(f"      msg        : {finding.message}")
    if finding.explanation:
        print(f"      explanation: {finding.explanation}")
    if finding.remediation:
        print(f"      remediation: {finding.remediation}")


def _print_policy_decision(decision: PolicyDecision) -> None:
    print(f"{Style.BRIGHT}=== Policy Decision ==={Style.RESET_ALL}")
    color = _ACTION_COLORS.get(decision.action, Fore.WHITE)
    print(f"  Azione: {color}{decision.action.value.upper()}{Style.RESET_ALL}")
    if decision.winning_policy is not None:
        print(
            f"  Policy vincente: {decision.winning_policy.id} "
            f"(priority={decision.winning_policy.priority})"
        )
    if decision.triggered_policies:
        print("  Policy attivate:")
        for policy in decision.triggered_policies:
            print(f"    - [{policy.action.value}] {policy.id}: {policy.message}")
    else:
        print("  Nessuna policy attivata.")
    print()


def _print_intelligence(
    labels: list[PromptLabel],
    explanation: RiskExplanation,
) -> None:
    print(f"{Style.BRIGHT}=== Prompt Intelligence ==={Style.RESET_ALL}")
    print("Classificazione:")
    for lab in labels:
        print(f"  - {lab.label} (confidence={lab.confidence:.2f})")
        for ev in lab.evidence:
            print(f"      · {ev}")
    print()
    print(f"{Style.BRIGHT}Spiegazione rischio:{Style.RESET_ALL}")
    print(f"  {explanation.summary}")
    if explanation.risk_factors:
        print("  Fattori di rischio:")
        for factor in explanation.risk_factors:
            print(f"    • {factor}")
    print(
        f"  Sicuro dopo sanitizzazione: "
        f"{'sì' if explanation.safe_after_sanitization else 'no'}"
    )
    action_color = {
        "BLOCK": Fore.RED,
        "SANITIZE": Fore.YELLOW,
        "REVIEW": Fore.YELLOW,
        "ALLOW": Fore.GREEN,
    }.get(explanation.recommended_action, Fore.WHITE)
    print(
        f"  Azione consigliata: "
        f"{action_color}{explanation.recommended_action}{Style.RESET_ALL}"
    )
    print()


def _print_result(
    result: AnalysisResult,
    breakdown: RiskBreakdown,
    decision: PolicyDecision,
) -> None:
    print()
    print(f"{Style.BRIGHT}=== PromptShield Analysis ==={Style.RESET_ALL}")
    print(f"Findings: {len(result.findings)}")
    if not result.findings:
        print(f"  {Fore.GREEN}Nessun finding rilevato.{Style.RESET_ALL}")
    else:
        for i, finding in enumerate(result.findings, start=1):
            _print_finding(finding, i)

    band = result.risk.band
    band_color = _BAND_COLORS[band]
    label = _BAND_LABELS[band]
    print()
    print(
        f"{Style.BRIGHT}Risk score:{Style.RESET_ALL} "
        f"{band_color}{result.risk.score}/100 — {label}{Style.RESET_ALL}"
    )
    print()
    print(breakdown.format_text())
    print()
    _print_policy_decision(decision)


def _print_sanitization(result: SanitizationResult) -> None:
    print(f"{Style.BRIGHT}=== Sanitizzazione ==={Style.RESET_ALL}")
    print(
        f"Sostituzioni: {result.replacements}  |  "
        f"Finding saltati (overlap/altro): {result.skipped}"
    )
    if result.replaced_findings:
        print(f"{Style.BRIGHT}Sostituzioni effettuate:{Style.RESET_ALL}")
        for finding in result.replaced_findings:
            token = finding.replacement_token
            label = label_for_token(token, finding)
            print(f"  {label:<22} -> {token}")
    else:
        print("  (nessuna sostituzione)")
    print()
    print(f"{Style.BRIGHT}Prompt sanitizzato:{Style.RESET_ALL}")
    print(result.sanitized_prompt)
    print()


def _read_user_line(prompt_text: str) -> str:
    if sys.stdin.isatty():
        try:
            return input(prompt_text).strip().lower()
        except EOFError:
            return ""

    if sys.platform == "win32":
        try:
            with open("CONIN$", encoding="utf-8", errors="replace") as console:
                sys.stderr.write(prompt_text)
                sys.stderr.flush()
                return console.readline().strip().lower()
        except OSError:
            return ""

    try:
        with open("/dev/tty", encoding="utf-8") as tty:
            sys.stderr.write(prompt_text)
            sys.stderr.flush()
            return tty.readline().strip().lower()
    except OSError:
        return ""


def _ask_yes(prompt_text: str, *, yes_values: set[str]) -> bool:
    answer = _read_user_line(prompt_text)
    return answer in yes_values


def _ask_send_original() -> bool:
    return _ask_yes(
        "Procedere con l'invio? (y/N) ",
        yes_values={"y", "yes", "s", "si", "sì"},
    )


def _ask_send_sanitized() -> bool:
    return _ask_yes(
        "Inviare il prompt sanitizzato? (y/N) ",
        yes_values={"y", "yes", "s", "si", "sì"},
    )


def _ask_offer_sanitize() -> bool:
    return _ask_yes(
        "Vuoi sanificare il prompt prima di inviarlo? (s/N) ",
        yes_values={"s", "si", "sì", "y", "yes"},
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="promptshield",
        description=(
            "Firewall per prompt inviati a LLM: detector modulari, risk score, "
            "policy engine YAML, sanitizzazione e report JSON per CI/CD."
        ),
    )
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        default=None,
        help="Leggi il prompt da un file invece che da stdin.",
    )
    parser.add_argument(
        "-r",
        "--rules",
        type=Path,
        default=None,
        help="Percorso a rules.yaml (default: config/rules.yaml).",
    )
    parser.add_argument(
        "--policy-file",
        type=Path,
        default=None,
        help="Percorso a policies.yaml (default: config/policies.yaml).",
    )
    parser.add_argument(
        "-p",
        "--plugins-dir",
        type=Path,
        default=None,
        help="Directory dei plugin detector (default: ./plugins).",
    )
    parser.add_argument(
        "-s",
        "--sanitize",
        action="store_true",
        help=(
            "Dopo l'analisi, oscura i finding con i replacement_token "
            "e proponi l'invio del prompt sanitizzato."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Emette un report JSON strutturato su stdout (metadati, findings "
            "redatti, breakdown, policy_decision, exit code)."
        ),
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help=(
            "Classifica il tipo di contenuto del prompt e spiega il rischio "
            "in linguaggio naturale (sezione intelligence nel JSON)."
        ),
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help=(
            "Non chiedere conferma; simula l'invio se le policy lo consentono. "
            "Una policy block impedisce l'invio anche con -y."
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disabilita i colori ANSI.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Abilita logging di debug su stderr.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {get_package_version()}",
    )
    return parser


def _refuse_blocked(
    decision: PolicyDecision, *, interactive: bool, risk_exit: int
) -> int:
    """Print block message and return appropriate exit code."""
    print(
        f"{Fore.RED}INVIO BLOCCATO da policy"
        f"{Style.RESET_ALL}"
        + (f" ({decision.winning_policy.id})" if decision.winning_policy else "")
    )
    for msg in decision.messages:
        print(f"  -> {msg}")
    if interactive:
        return 0
    return risk_exit


def run_serve(argv: list[str] | None = None) -> int:
    """Start the Enterprise API (uvicorn)."""
    parser = argparse.ArgumentParser(
        prog="promptshield serve",
        description="Avvia PromptShield Enterprise API (FastAPI/uvicorn).",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default 0.0.0.0)")
    parser.add_argument(
        "--port", type=int, default=8000, help="Bind port (default 8000)"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Abilita auto-reload (solo sviluppo).",
    )
    args = parser.parse_args(argv)
    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn non installato. Esegui: pip install 'promptshield[api]' "
            "oppure pip install uvicorn fastapi",
            file=sys.stderr,
        )
        return 1
    uvicorn.run(
        "promptshield.api.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
    return 0


def run_dashboard(argv: list[str] | None = None) -> int:
    """Start the API server and print the dashboard URL."""
    parser = argparse.ArgumentParser(
        prog="promptshield dashboard",
        description="Avvia il server e mostra l'URL della dashboard admin.",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args(argv)
    display_host = "127.0.0.1" if args.host in {"0.0.0.0", "::"} else args.host
    print(
        f"PromptShield Dashboard -> http://{display_host}:{args.port}/dashboard\n"
        f"API docs              -> http://{display_host}:{args.port}/docs\n"
        "Set PROMPTSHIELD_DASHBOARD_KEY to require authentication."
    )
    return run_serve(
        ["--host", args.host, "--port", str(args.port)]
        + (["--reload"] if args.reload else [])
    )


def run_cleanup(argv: list[str] | None = None) -> int:
    """Enforce retention policy (delete old analyses / audit events)."""
    parser = argparse.ArgumentParser(
        prog="promptshield cleanup",
        description="Elimina analisi ed eventi più vecchi di N giorni.",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Giorni di retention (default: PROMPTSHIELD_RETENTION_DAYS o 90).",
    )
    args = parser.parse_args(argv)
    from promptshield.persistence.cleanup import enforce_retention_policy

    result = enforce_retention_policy(args.days)
    print(
        f"Cleanup completato: retention={result['retention_days']}d "
        f"deleted_analyses={result['deleted_analyses']} "
        f"deleted_events={result['deleted_events']} "
        f"cutoff={result['cutoff']}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``promptshield`` console script."""
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "serve":
        return run_serve(raw[1:])
    if raw and raw[0] == "dashboard":
        return run_dashboard(raw[1:])
    if raw and raw[0] == "cleanup":
        return run_cleanup(raw[1:])

    parser = build_arg_parser()
    args = parser.parse_args(raw)
    _configure_logging(args.verbose)

    colorama_init(strip=bool(args.no_color or args.json), convert=True)

    interactive = sys.stdin.isatty() and not args.json

    try:
        prompt = _read_prompt(args.file)
    except OSError as exc:
        print(f"Errore lettura prompt: {exc}", file=sys.stderr)
        return 1

    if not prompt.strip():
        print("Prompt vuoto: nulla da analizzare.", file=sys.stderr)
        return 1

    try:
        service: PromptShieldService = build_service(
            rules_path=args.rules,
            plugins_dir=args.plugins_dir,
            policy_file=args.policy_file,
        )
        outcome = service.analyze(
            prompt,
            {
                "sanitize": bool(args.sanitize),
                "explain": bool(args.explain),
            },
        )
    except Exception as exc:
        logger.exception("Analysis failed")
        print(f"Errore durante l'analisi: {exc}", file=sys.stderr)
        return 1

    result = outcome.analysis
    decision = outcome.decision
    breakdown = outcome.breakdown
    final_exit = outcome.exit_code
    findings_list = outcome.findings
    labels = outcome.labels
    explanation = outcome.explanation
    san = outcome.sanitization

    # ----- JSON / CI mode -----
    if args.json:
        print(json.dumps(outcome.to_report_dict(), ensure_ascii=False, indent=2))
        return final_exit

    # ----- Human-readable path -----
    _print_result(result, breakdown, decision)
    if explanation is not None:
        _print_intelligence(labels, explanation)

    # Hard policy block: never send, even with -y / sanitize.
    if decision.blocked:
        return _refuse_blocked(decision, interactive=interactive, risk_exit=final_exit)

    # Explicit allow from a winning allow-policy: send without further prompts
    # when -y, or offer standard flow otherwise. High risk still shown above.
    policy_auto_allow = (
        decision.action is PolicyAction.ALLOW
        and decision.winning_policy is not None
        and decision.winning_policy.action is PolicyAction.ALLOW
    )

    if args.sanitize:
        if san is None:
            san = service.sanitizer.sanitize(prompt, findings_list)
        _print_sanitization(san)
        if args.yes or policy_auto_allow:
            print(
                f"{Fore.GREEN}Prompt sanitizzato inviato (simulazione){Style.RESET_ALL}"
            )
            return 0 if interactive else final_exit
        if interactive:
            _ask_send_sanitized()
            return 0
        if _ask_send_sanitized():
            print(
                f"{Fore.GREEN}Prompt sanitizzato inviato (simulazione){Style.RESET_ALL}"
            )
            return final_exit
        print(f"{Fore.YELLOW}Invio annullato.{Style.RESET_ALL}")
        return final_exit

    if args.yes or policy_auto_allow:
        if decision.action is PolicyAction.WARN:
            print(f"{Fore.YELLOW}Invio consentito con avviso policy.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Prompt inviato (simulazione){Style.RESET_ALL}")
        return 0 if interactive else final_exit

    if interactive:
        if result.risk.band == RiskBand.RED:
            if _ask_offer_sanitize():
                san = service.sanitizer.sanitize(prompt, findings_list)
                _print_sanitization(san)
                print(
                    f"{Fore.GREEN}Prompt sanitizzato inviato (simulazione)"
                    f"{Style.RESET_ALL}"
                )
                return 0
            _ask_send_original()
            return 0
        _ask_send_original()
        return 0

    # Non-interactive without -y
    if result.risk.band == RiskBand.RED:
        if _ask_offer_sanitize():
            san = service.sanitizer.sanitize(prompt, findings_list)
            _print_sanitization(san)
            print(
                f"{Fore.GREEN}Prompt sanitizzato inviato (simulazione){Style.RESET_ALL}"
            )
            return final_exit
        if _ask_send_original():
            print(f"{Fore.GREEN}Prompt inviato (simulazione){Style.RESET_ALL}")
            return final_exit
        print(f"{Fore.YELLOW}Invio annullato.{Style.RESET_ALL}")
        return final_exit

    if _ask_send_original():
        print(f"{Fore.GREEN}Prompt inviato (simulazione){Style.RESET_ALL}")
        return final_exit

    print(f"{Fore.YELLOW}Invio annullato.{Style.RESET_ALL}")
    return final_exit


if __name__ == "__main__":
    raise SystemExit(main())
