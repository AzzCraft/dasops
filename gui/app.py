import shlex
import tempfile
from pathlib import Path

import subprocess

import streamlit as st

from dasops.scaffold import create_product_repo
from dasops.vendor import SUPPORTED_PUBLIC_TIERS, build_install_cadence_command


def _write_temp_bytes(label: str, data: bytes) -> Path:
    """Persist Streamlit uploaded bytes to a temp file and return its path."""
    tmp = tempfile.NamedTemporaryFile(delete=False, prefix="dasops_", suffix=f"_{label}.md")
    tmp.write(data)
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


def main() -> None:
    st.set_page_config(page_title="DAS + OpenSpec Factory", layout="centered")
    st.title("DAS + OpenSpec Factory")

    st.markdown(
        """
This GUI creates a **new product repository** in a separate folder.

- **Factory repo (this repo)** = tooling + GUI + templates
- **Product repo (generated)** = where your AI workers build the software

Recommended:

- Put product repos under `~/projects/`
- Keep the factory under `~/tools/`

This physical isolation prevents AI agents from accidentally running/modifying the factory GUI instead of your product.
"""
    )

    factory_root = Path(__file__).resolve().parents[1]

    default_dest = str(Path.home() / "projects" / "my-product")
    dest = st.text_input("Product repo output directory", value=default_dest)

    standard_release = st.selectbox("DAS Standard release", ["1.4.0", "1.5.0-beta.1"])
    selected_suite = st.text_input("Fixed synced Suite workspace (required for 1.5)", value="") if standard_release == "1.5.0-beta.1" else ""
    st.subheader("Input documents")
    master_file = st.file_uploader("Master Doc (master_doc.md)", type=["md", "markdown"])
    ui_file = st.file_uploader("UI Spec (ui_spec.md)", type=["md", "markdown"])

    headless_file = st.file_uploader("Headless Surface Note (when applicable)", type=["md", "markdown"]) if standard_release == "1.5.0-beta.1" else None
    context_file = st.file_uploader("Context Pack (L2)", type=["md", "markdown"]) if standard_release == "1.5.0-beta.1" else None
    extension_file = st.file_uploader("Local extensions (only real declarations)", type=["json"]) if standard_release == "1.5.0-beta.1" else None
    st.caption("The Master document declares interaction and conformance profiles; missing UI input does not imply headless.")
    st.subheader("Optional: create an initial change folder")
    change_id = st.text_input("Initial change id", value="initial")
    intent = st.text_input("Intent", value="Initial bootstrap")
    change_empty = st.checkbox(
        "OPSX mode: create EMPTY change folder (do NOT pre-create artifacts)",
        value=False,
        help="Use this when you want OpenSpec OPSX / IDE agent to generate artifacts from templates on demand.",
    )

    st.subheader("Options")
    init_git = st.checkbox("Initialize git repo (git init)", value=True)
    overwrite = st.checkbox("Overwrite non-empty destination (DANGEROUS)", value=False)
    allow_inside_factory = st.checkbox(
        "Advanced: allow creating product repo inside the factory folder (NOT recommended)",
        value=False,
    )

    st.subheader("Optional: vendor Cadence")
    install_cadence = st.checkbox("Install Cadence under vendor/cadence", value=False)
    cadence_tier = st.selectbox("Cadence tier", options=list(SUPPORTED_PUBLIC_TIERS), index=0)
    cadence_source_mode = st.radio(
        "Cadence source",
        options=["From DAS Suite", "Clone from Git base"],
        index=0,
        horizontal=True,
    )
    cadence_suite_path = st.text_input("DAS Suite path", value="")
    cadence_git_base = st.text_input(
        "Git base",
        value="",
        help="Leave empty unless you want clone-based install from a real Git base such as https://github.com/acme.",
    )
    cadence_org = st.text_input("Override org", value="")
    cadence_ssh = st.checkbox("Use SSH Git URLs", value=False)

    if st.button("Create product repo"):
        if not dest.strip():
            st.error("Please provide a destination directory.")
            return
        if master_file is None or (standard_release == "1.4.0" and ui_file is None):
            st.error("Please upload BOTH master_doc.md and ui_spec.md.")
            return

        if standard_release == "1.5.0-beta.1" and not selected_suite.strip():
            st.error("Select a fixed synced Suite workspace for Standard 1.5.")
            return
        dest_path = Path(dest).expanduser().absolute()
        if dest_path == factory_root or dest_path.is_relative_to(factory_root):
            if not allow_inside_factory:
                st.error(
                    "Refusing to create a product repo inside the factory repo. "
                    "Choose a different destination (recommended), or enable the Advanced override checkbox."
                )
                return

        vendor_cmd = None
        if install_cadence:
            try:
                vendor_cmd = build_install_cadence_command(
                    tier=cadence_tier,
                    from_suite=selected_suite.strip() if standard_release == "1.5.0-beta.1" else (cadence_suite_path.strip() if cadence_source_mode == "From DAS Suite" else None),
                    git_base=cadence_git_base.strip() if standard_release == "1.4.0" and cadence_source_mode == "Clone from Git base" else None,
                    org=(cadence_org.strip() or None) if standard_release == "1.4.0" and cadence_source_mode == "Clone from Git base" else None,
                    use_ssh=cadence_ssh if standard_release == "1.4.0" and cadence_source_mode == "Clone from Git base" else False,
                )
            except ValueError as exc:
                st.error(str(exc))
                return
        master_path = _write_temp_bytes("master_doc", master_file.getvalue())
        ui_path = _write_temp_bytes("ui_spec", ui_file.getvalue()) if ui_file else None
        headless_path = _write_temp_bytes("headless", headless_file.getvalue()) if headless_file else None
        context_path = _write_temp_bytes("context", context_file.getvalue()) if context_file else None
        extension_path = _write_temp_bytes("extension", extension_file.getvalue()) if extension_file else None

        try:
            out = create_product_repo(
                factory_root=factory_root,
                dest_dir=dest_path,
                master_doc_path=master_path,
                ui_spec_path=ui_path,
                standard_release=standard_release,
                from_suite=Path(selected_suite) if selected_suite else None,
                headless_note_path=headless_path,
                context_pack_path=context_path,
                extension_manifest_path=extension_path,
                change_id=(change_id.strip() or None),
                intent=intent.strip(),
                init_git=init_git,
                overwrite=overwrite,
                change_empty=change_empty,
            )
            st.success(f"Created product repo: {out}")
            if standard_release == "1.5.0-beta.1":
                from dasops.scaffold_v15 import verify
                st.json(verify(out, scope="scaffold"))
            if vendor_cmd is not None:
                result = subprocess.run(vendor_cmd, cwd=str(out), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                if result.returncode:
                    st.error(f"Product repo was created at {out}; Cadence installation failed. Keep it and retry only installation.")
                else:
                    st.success("Cadence installed under vendor/cadence")
                st.code(result.stdout or "", language="bash")
            st.code(f"cd {shlex.quote(str(out))}\n./scripts/verify", language="bash")
            # CLI-equivalent hints for GUI-vs-CLI parity.
            # These ensure the GUI user knows the corresponding CLI commands.
            # Status values: TODO, IN_PROGRESS, DONE, BLOCKED, PROPOSED
            st.info(
                "**Next steps (CLI equivalents):**\n"
                "- Health check: `dasops doctor`\n"
                "- Start a task: `dasops start-task --change-id <change-id> --task-id <id>`\n"
                "- Claim ready: `dasops claim-ready --change-id <change-id>`\n"
                "- Verify sub-systems: `scripts/verify-backend`, `scripts/verify-frontend`\n"
                "- Frontend gate checks matrix structure and evidence-file presence; visual comparison requires your product's actual UI tests\n"
                "- Cadence host-local stays `mode=host-launcher`; non-host profiles use `mode=runtime-exec` and fail closed unless `CADENCE_SANDBOX_CONTAINER_ADAPTER` or `CADENCE_SANDBOX_MICROVM_ADAPTER` returns verified runtime proof."
            )
        except (SystemExit, RuntimeError) as e:
            st.error(str(e))
        except Exception as e:
            st.exception(e)
        finally:
            for path in (master_path, ui_path, headless_path, context_path, extension_path):
                if path is not None: path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
